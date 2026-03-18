'use strict';

importScripts('https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js', 'ClassFileReader.js', 'scan-engine.js');

const postProgress = (step, label, current, total) => {
  postMessage({ type: 'progress', step, label, current, total });
};

self.onmessage = async (e) => {
  const msg = e.data || {};
  if (msg.type !== 'scan') return;

  const t0 = Date.now();
  const buf = msg.buffer;
  const fileName = msg.fileName || 'unknown.jar';
  const fileSize = msg.fileSize || 0;

  try {
    postProgress(0, 'Extracting…', 0, 1);
    let zip = await JSZip.loadAsync(buf);
    const all = Object.keys(zip.files);
    const clsFiles = all.filter(f => f.endsWith('.class'));
    const resFiles = all.filter(f => !f.endsWith('/') && !f.endsWith('.class'));
    const binFiles = resFiles.filter(f => ScanEngine.isBinaryResource(f));
    const textResFiles = resFiles.filter(f => !ScanEngine.isBinaryResource(f));
    const totalFiles = clsFiles.length + textResFiles.length + binFiles.length;

    postProgress(1, 'Config + hashes…', 0, 1);
    const platform = ScanEngine.detectPlatform(zip.files, resFiles);
    const mainClass = await ScanEngine.extractMainClass(zip.files);
    const [sha, md5v] = await Promise.all([
      ScanEngine.sha256(buf),
      Promise.resolve(ScanEngine.md5(buf)),
    ]);

    if (ScanEngine.isAllowlistedSha256(sha)) {
      postMessage({
        type: 'done',
        report: {
          verdict: 'CLEAN',
          totalScore: 0,
          findings: [],
          families: [],
          classResults: [],
          totalClasses: 0,
          platform,
          mainClass,
          sha256: sha,
          md5: md5v,
          scanMs: Date.now() - t0,
          fileName,
          fileSize,
          allowlisted: true,
        }
      });
      return;
    }

    postProgress(2, `Scanning 0/${totalFiles} files…`, 0, totalFiles);
    const classResults = [];
    const allFindings = [];
    const methodCandidates = [];
    const mixinTargets = [];

    for (let i = 0; i < clsFiles.length; i++) {
      const cn = clsFiles[i];
      let rb = await zip.files[cn].async('arraybuffer');
      try {
        const parsed = ScanEngine.readClassConstants(rb);
        const strings = parsed.strings || [];
        const resolvedMethods = parsed.resolvedMethods || [];
        const resolvedFields = parsed.resolvedFields || [];
        const bytecodeFlags = parsed.bytecodeFlags || { hasXor: false, hasArrayOps: false };
        const matchStrings = strings.concat(resolvedMethods, resolvedFields);
        methodCandidates.push(...strings);
        const ent = ScanEngine.byteEntropy(new Uint8Array(rb));
        const findings = ScanEngine.matchSignatures(cn, matchStrings, 'class', bytecodeFlags);
        classResults.push({
          name: cn,
          strings,
          findings,
          score: Math.min(findings.reduce((s, f) => s + (f.score || 0), 0), 100),
          entropy: ent,
        });
        allFindings.push(...findings);
      } catch (err) {
        allFindings.push({
          id: 'class_parse_error',
          severity: 'MED',
          category: 'obfusc',
          title: 'Class parse error (possible obfuscation or corrupt class)',
          detail: err?.message || 'Class parse failed',
          sourceFile: cn,
          score: 8,
          note: 'ClassFileReader could not parse bytecode. This may indicate obfuscation or malformed class.'
        });
      } finally {
        rb = null;
      }
      if (i % 6 === 0) {
        postProgress(2, `Scan files (${i + 1}/${totalFiles})`, i + 1, totalFiles);
      }
    }

    let resIndex = 0;
    for (const fn of textResFiles) {
      try {
        const content = await zip.files[fn].async('string');
        const lines = content.split(/\r?\n/).filter(l => l.trim().length);
        if (/mixins\.json$/i.test(fn)) {
          const info = ScanEngine.extractMixinTargets(content);
          if (info.mixins.length || info.targets.length) mixinTargets.push(info);
        }
        const findings = ScanEngine.matchSignatures(fn, lines, 'text');
        if (findings.length) {
          classResults.push({
            name: '[res] ' + fn,
            strings: lines,
            findings,
            score: Math.min(findings.reduce((s, f) => s + (f.score || 0), 0), 100),
            entropy: 0,
          });
        }
        allFindings.push(...findings);
      } catch (_) {}
      resIndex++;
      postProgress(2, `Scan files (${clsFiles.length + resIndex}/${totalFiles})`, clsFiles.length + resIndex, totalFiles);
    }

    postProgress(3, `Scanning ${binFiles.length} binary resources…`, 0, binFiles.length || 1);
    let binIndex = 0;
    for (const fn of binFiles) {
      try {
        let rb = await zip.files[fn].async('arraybuffer');
        const hits = ScanEngine.scanBinaryResource(fn, rb);
        allFindings.push(...hits);
        const strings = ScanEngine.extractBinaryStrings(rb, 4);
        classResults.push({
          name: '[bin] ' + fn,
          strings,
          findings: hits,
          score: Math.min(hits.reduce((s, f) => s + (f.score || 0), 0), 100),
          entropy: ScanEngine.byteEntropy(new Uint8Array(rb)),
        });
        rb = null;
      } catch (_) {}
      binIndex++;
      postProgress(3, `Binary scan (${binIndex}/${binFiles.length})`, binIndex, binFiles.length || 1);
    }

    allFindings.push(...ScanEngine.matchFileSignatures(resFiles));

    postProgress(4, 'Scoring…', 0, 1);
    allFindings.push(...ScanEngine.obfuscationMetrics(clsFiles, methodCandidates, classResults));
    if (mixinTargets.length) {
      for (const info of mixinTargets) {
        allFindings.push(...ScanEngine.matchMixinTargets(info));
      }
    }
    const deduped = ScanEngine.deduplicate(allFindings);
    deduped.sort((a, b) => {
      const to = { stealer: 0, botnet: 1, rat: 2, loader: 3, spyware: 4, dropper: 5, obfusc: 6 };
      const so = { HIGH: 0, MED: 1, LOW: 2, INFO: 3 };
      return (to[a.category] ?? 7) - (to[b.category] ?? 7) || (so[a.severity] || 3) - (so[b.severity] || 3) || (b.score - a.score);
    });
    const severityBoost = f => (f.severity === 'HIGH' ? 1 : f.severity === 'MED' ? 0.7 : 0.4);
    const genericPenalty = f => (f.family && f.family.toLowerCase().includes('generic') ? 0.7 : 1);
    const weightedTotal = deduped.reduce((s, f) => s + (f.score || 0) * severityBoost(f) * genericPenalty(f), 0);
    const totalScore = Math.min(Math.round(weightedTotal), 100);
    const hasCritical = deduped.some(f => f.severity === 'HIGH' && (f.score || 0) >= 50);
    const verdict = hasCritical || totalScore >= 70 ? 'MALICIOUS' : totalScore >= 35 ? 'SUSPICIOUS' : 'CLEAN';
    const families = ScanEngine.detectFamilies(deduped);

    const report = {
      verdict,
      totalScore,
      findings: deduped,
      families,
      classResults,
      totalClasses: clsFiles.length,
      platform,
      mainClass,
      sha256: sha,
      md5: md5v,
      scanMs: Date.now() - t0,
      fileName,
      fileSize,
    };

    postMessage({ type: 'done', report });
  } catch (err) {
    postMessage({ type: 'error', message: err?.message || String(err) });
  } finally {
    try {
      zip = null;
    } catch (_) {}
  }
};
