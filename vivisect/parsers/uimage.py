import gzip
import logging

import envi

import vstruct.defs.uimage as v_uimage

import vivisect.const as v_const
import vivisect.exc as v_exc
import vivisect.parsers as v_parsers

logger = logging.getLogger(__name__)


archcalls = {
    'i386': 'cdecl',
    'amd64': 'sysvamd64call',
    'arm': 'armcall',
    'thumb': 'armcall',
    'thumb16': 'armcall',
}


# Map U-Boot ih_arch codes onto vivisect architecture names.  Codes which
# have no envi backend yet are intentionally omitted.
uimage_archs = {
    v_uimage.IH_ARCH_ARM: 'arm',
    v_uimage.IH_ARCH_ARM64: 'aarch64',
    v_uimage.IH_ARCH_I386: 'i386',
    v_uimage.IH_ARCH_X86_64: 'amd64',
    v_uimage.IH_ARCH_MICROBLAZE: 'arm',
}


def parseBytes(vw, bytez, filename='uimage', baseaddr=None):
    '''
    Parse a U-Boot legacy uImage out of the provided bytes and populate the
    workspace with its segment map and entry point.
    '''
    if not v_uimage.isUImage(bytez):
        raise v_exc.CorruptFile('uimage', 'bad image magic')

    header = v_uimage.UImageHeader()
    header.vsParse(bytez[:v_uimage.IH_HDR_SIZE])

    payload_size = int(header.ih_size)
    loadaddr = int(header.ih_load)
    entry = int(header.ih_ep)
    comp = int(header.ih_comp)

    payload = bytez[v_uimage.IH_HDR_SIZE:v_uimage.IH_HDR_SIZE + payload_size]
    if len(payload) != payload_size:
        raise v_exc.CorruptFile(
            'uimage',
            'declared payload size %d but only %d bytes present' % (payload_size, len(payload)),
        )

    arch = vw.config.viv.parsers.uimage.arch
    if not arch:
        arch = uimage_archs.get(int(header.ih_arch), '')
    if not arch:
        raise Exception(
            'uImage loader *requires* arch option '
            '(-O viv.parsers.uimage.arch=\\"<archname>\\")'
        )

    try:
        envi.getArchModule(arch)
    except Exception:
        raise v_exc.InvalidArchitecture('uimage', arch) from None

    if baseaddr is not None:
        # relocate both load address and entry point together
        delta = baseaddr - loadaddr
        loadaddr = baseaddr
        entry += delta

    bigend = vw.config.viv.parsers.uimage.bigend

    vw.setMeta('Architecture', arch)
    vw.setMeta('Platform', 'Unknown')
    vw.setMeta('Format', 'uimage')
    vw.setMeta('bigend', bigend)
    vw.setMeta('DefaultCall', archcalls.get(arch, 'unknown'))

    fname = vw.addFile(filename, loadaddr, v_parsers.md5Bytes(bytez))
    vw.setFileMeta(fname, 'sha256', v_parsers.sha256Bytes(bytez))
    vw.setFileMeta(fname, 'uimage_name', header.getImageName())
    vw.setFileMeta(fname, 'uimage_loadaddr', int(header.ih_load))
    vw.setFileMeta(fname, 'uimage_entry', int(header.ih_ep))
    vw.setFileMeta(fname, 'uimage_comp', comp)

    if comp == v_uimage.IH_COMP_GZIP:
        try:
            payload = gzip.decompress(payload)
        except OSError as exc:
            raise v_exc.CorruptFile('uimage', 'gzip decompress failed: %s' % exc) from None
        vw.setFileMeta(fname, 'uimage_uncompressed_size', len(payload))
    elif comp != v_uimage.IH_COMP_NONE:
        logger.warning(
            'uImage compression type %d is not supported; loading compressed bytes',
            comp,
        )

    # Map the image header immediately before the load address so the full
    # on-disk image is available while the payload lands at ih_load, exactly
    # where the boot loader would place it.
    hdraddr = loadaddr - v_uimage.IH_HDR_SIZE
    vw.addMemoryMap(hdraddr, 7, fname, bytez[:v_uimage.IH_HDR_SIZE])
    vw.addSegment(hdraddr, v_uimage.IH_HDR_SIZE, 'uimage_header', fname)

    vw.addMemoryMap(loadaddr, 7, fname, payload)
    vw.addSegment(loadaddr, len(payload), '%.8x' % loadaddr, fname)

    if entry is not None:
        vw.addExport(entry, v_const.EXP_FUNCTION, '__entry', fname, makeuniq=True)
        logger.info('adding function from uImage metadata: 0x%x (_entry)', entry)
        vw.addEntryPoint(entry)


def parseFile(vw, filename, baseaddr=None):
    with open(filename, 'rb') as f:
        bytez = f.read()
    parseBytes(vw, bytez, filename=filename, baseaddr=baseaddr)


def parseFd(vw, fd, filename=None, baseaddr=None):
    fd.seek(0)
    bytez = fd.read()
    if filename is None:
        filename = 'uimage' if baseaddr is None else 'uimage_%.8x' % baseaddr
    parseBytes(vw, bytez, filename=filename, baseaddr=baseaddr)


def parseMemory(vw, memobj, baseaddr):
    raise NotImplementedError('uimage loader cannot parse memory!')


def getMemBaseAndSize(vw, filename, baseaddr=None):
    '''
    Return the default base address and total memory size needed to load the
    uImage.  The header segment sits immediately before the payload segment.
    '''
    with open(filename, 'rb') as f:
        bytez = f.read(v_uimage.IH_HDR_SIZE)

    header = v_uimage.UImageHeader()
    header.vsParse(bytez)

    loadaddr = int(header.ih_load)
    if baseaddr:
        loadaddr = baseaddr

    size = v_uimage.IH_HDR_SIZE + int(header.ih_size)
    return loadaddr - v_uimage.IH_HDR_SIZE, size
