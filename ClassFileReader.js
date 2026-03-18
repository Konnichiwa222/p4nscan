'use strict';

// JVM ClassFileReader — strict constant pool parser + ref resolver
const ClassFileReader = (() => {
  const TAGS = {
    Utf8: 1,
    Integer: 3,
    Float: 4,
    Long: 5,
    Double: 6,
    Class: 7,
    String: 8,
    Fieldref: 9,
    Methodref: 10,
    InterfaceMethodref: 11,
    NameAndType: 12,
    MethodHandle: 15,
    MethodType: 16,
    InvokeDynamic: 18,
    Dynamic: 17,
    Module: 19,
    Package: 20,
  };

  function assertBounds(view, o, size) {
    if (o + size > view.byteLength) {
      throw new Error('offset out of bounds');
    }
  }
  function readU1(view, o) { assertBounds(view, o, 1); return view.getUint8(o); }
  function readU2(view, o) { assertBounds(view, o, 2); return view.getUint16(o, false); }
  function readU4(view, o) { assertBounds(view, o, 4); return view.getUint32(o, false); }

  function decodeModifiedUtf8(bytes, start, length) {
    let out = '';
    let i = start;
    const end = start + length;
    while (i < end) {
      const b = bytes[i++];
      if ((b & 0x80) === 0) {
        out += String.fromCharCode(b);
        continue;
      }
      if ((b & 0xE0) === 0xC0) {
        const b2 = bytes[i++];
        const code = ((b & 0x1F) << 6) | (b2 & 0x3F);
        out += String.fromCharCode(code);
        continue;
      }
      if ((b & 0xF0) === 0xE0) {
        const b2 = bytes[i++];
        const b3 = bytes[i++];
        const code = ((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F);
        out += String.fromCharCode(code);
        continue;
      }
      out += '\uFFFD';
    }
    return out;
  }

  function parse(buf) {
    const view = new DataView(buf);
    const bytes = new Uint8Array(buf);
    let o = 0;

    if (readU4(view, o) !== 0xCAFEBABE) {
      throw new Error('Invalid class file magic');
    }
    o += 4;
    o += 4; // minor_version + major_version

    const cpCount = readU2(view, o);
    o += 2;
    const cp = new Array(cpCount);

    for (let i = 1; i < cpCount; i++) {
      const tag = readU1(view, o);
      o += 1;
      switch (tag) {
        case TAGS.Utf8: {
          const len = readU2(view, o);
          o += 2;
          const str = decodeModifiedUtf8(bytes, o, len);
          cp[i] = { tag, value: str };
          o += len;
          break;
        }
        case TAGS.Integer:
        case TAGS.Float:
          o += 4;
          cp[i] = { tag };
          break;
        case TAGS.Long:
        case TAGS.Double:
          o += 8;
          cp[i] = { tag };
          i++;
          break;
        case TAGS.Class: {
          const nameIndex = readU2(view, o);
          o += 2;
          cp[i] = { tag, nameIndex };
          break;
        }
        case TAGS.String: {
          const stringIndex = readU2(view, o);
          o += 2;
          cp[i] = { tag, stringIndex };
          break;
        }
        case TAGS.Fieldref:
        case TAGS.Methodref:
        case TAGS.InterfaceMethodref: {
          const classIndex = readU2(view, o);
          const nameAndTypeIndex = readU2(view, o + 2);
          o += 4;
          cp[i] = { tag, classIndex, nameAndTypeIndex };
          break;
        }
        case TAGS.NameAndType: {
          const nameIndex = readU2(view, o);
          const descriptorIndex = readU2(view, o + 2);
          o += 4;
          cp[i] = { tag, nameIndex, descriptorIndex };
          break;
        }
        case TAGS.InvokeDynamic:
        case TAGS.Dynamic: {
          const bootstrapMethodAttrIndex = readU2(view, o);
          const nameAndTypeIndex = readU2(view, o + 2);
          o += 4;
          cp[i] = { tag, bootstrapMethodAttrIndex, nameAndTypeIndex };
          break;
        }
        case TAGS.MethodHandle: {
          const refKind = readU1(view, o);
          const refIndex = readU2(view, o + 1);
          o += 3;
          cp[i] = { tag, refKind, refIndex };
          break;
        }
        case TAGS.MethodType: {
          const descriptorIndex = readU2(view, o);
          o += 2;
          cp[i] = { tag, descriptorIndex };
          break;
        }
        case TAGS.Module:
        case TAGS.Package: {
          const nameIndex = readU2(view, o);
          o += 2;
          cp[i] = { tag, nameIndex };
          break;
        }
        default:
          throw new Error(`Unknown constant pool tag: ${tag}`);
      }
    }

    const strings = [];
    const classNames = [];
    const resolvedMethods = new Set();
    const resolvedFields = new Set();

    const utf = (idx) => {
      const e = cp[idx];
      return e && e.tag === TAGS.Utf8 ? e.value : null;
    };
    const className = (idx) => {
      const e = cp[idx];
      if (!e || e.tag !== TAGS.Class) return null;
      return utf(e.nameIndex);
    };
    const nameAndType = (idx) => {
      const e = cp[idx];
      if (!e || e.tag !== TAGS.NameAndType) return null;
      const name = utf(e.nameIndex);
      const desc = utf(e.descriptorIndex);
      return name && desc ? { name, desc } : null;
    };
    const resolveRef = (entry) => {
      if (!entry) return null;
      if (entry.tag === TAGS.Methodref || entry.tag === TAGS.InterfaceMethodref) {
        const cn = className(entry.classIndex);
        const nt = nameAndType(entry.nameAndTypeIndex);
        return cn && nt ? { kind: 'method', value: `${cn}.${nt.name}:${nt.desc}` } : null;
      }
      if (entry.tag === TAGS.Fieldref) {
        const cn = className(entry.classIndex);
        const nt = nameAndType(entry.nameAndTypeIndex);
        return cn && nt ? { kind: 'field', value: `${cn}.${nt.name}:${nt.desc}` } : null;
      }
      return null;
    };

    for (let i = 1; i < cpCount; i++) {
      const entry = cp[i];
      if (!entry) continue;
      if (entry.tag === TAGS.Utf8 && entry.value) {
        strings.push(entry.value);
      } else if (entry.tag === TAGS.String) {
        const s = utf(entry.stringIndex);
        if (s) strings.push(s);
      } else if (entry.tag === TAGS.Class) {
        const cn = utf(entry.nameIndex);
        if (cn) classNames.push(cn);
      } else if (entry.tag === TAGS.Methodref || entry.tag === TAGS.InterfaceMethodref || entry.tag === TAGS.Fieldref) {
        const resolved = resolveRef(entry);
        if (resolved && resolved.kind === 'method') resolvedMethods.add(resolved.value);
        if (resolved && resolved.kind === 'field') resolvedFields.add(resolved.value);
      } else if (entry.tag === TAGS.MethodHandle) {
        const ref = cp[entry.refIndex];
        const resolved = resolveRef(ref);
        if (resolved && resolved.kind === 'method') resolvedMethods.add(resolved.value);
        if (resolved && resolved.kind === 'field') resolvedFields.add(resolved.value);
      }
    }

    const bytecodeFlags = { hasXor: false, hasArrayOps: false };

    const skipAttributes = (view, offset, count) => {
      let o2 = offset;
      for (let i = 0; i < count; i++) {
        readU2(view, o2);
        const attrLen = readU4(view, o2 + 2);
        o2 += 6 + attrLen;
      }
      return o2;
    };

    const scanCode = (bytesArr) => {
      for (let i = 0; i < bytesArr.length; i++) {
        const op = bytesArr[i];
        if (op === 0x82 || op === 0x83) bytecodeFlags.hasXor = true; // ixor/lxor
        if (op === 0xBC || op === 0xBE || op === 0x33 || op === 0x54 || op === 0x51 || op === 0x55) {
          bytecodeFlags.hasArrayOps = true; // newarray/arraylength/baload/bastore/caload/castore
        }
        if (bytecodeFlags.hasXor && bytecodeFlags.hasArrayOps) return;
      }
    };

    // Parse remainder of class file for method bytecode
    readU2(view, o); o += 2;
    readU2(view, o); o += 2;
    readU2(view, o); o += 2;
    const interfacesCount = readU2(view, o); o += 2 + interfacesCount * 2;

    const fieldsCount = readU2(view, o); o += 2;
    for (let i = 0; i < fieldsCount; i++) {
      o += 6; // access_flags, name_index, descriptor_index
      const attrCount = readU2(view, o); o += 2;
      o = skipAttributes(view, o, attrCount);
    }

    const methodsCount = readU2(view, o); o += 2;
    for (let i = 0; i < methodsCount; i++) {
      o += 6; // access_flags, name_index, descriptor_index
      const attrCount = readU2(view, o); o += 2;
      for (let a = 0; a < attrCount; a++) {
        const attrName = utf(readU2(view, o));
        const attrLen = readU4(view, o + 2);
        o += 6;
        if (attrName === 'Code') {
          const codeLen = readU4(view, o + 4);
          const codeStart = o + 8;
          const codeEnd = codeStart + codeLen;
          if (codeEnd <= bytes.length) {
            scanCode(bytes.subarray(codeStart, codeEnd));
          }
          const exCount = readU2(view, codeEnd);
          const exTableEnd = codeEnd + 2 + exCount * 8;
          const codeAttrCount = readU2(view, exTableEnd);
          o = skipAttributes(view, exTableEnd + 2, codeAttrCount);
        } else {
          o += attrLen;
        }
        if (bytecodeFlags.hasXor && bytecodeFlags.hasArrayOps) break;
      }
    }

    return {
      strings,
      classNames,
      resolvedMethods: Array.from(resolvedMethods),
      resolvedFields: Array.from(resolvedFields),
      constantPool: cp,
      constantPoolCount: cpCount,
      bytecodeFlags,
    };
  }

  return { parse, TAGS };
})();

if (typeof module !== 'undefined') module.exports = ClassFileReader;
