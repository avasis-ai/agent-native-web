import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import { HttpError, clone } from './util.mjs';

const WIDTH = 600;
const HEIGHT = 400;
const PANEL = { x: 530, y: 330, width: 50, height: 50 };

const entries = {
  'media:trailpack-blue:hero': {
    kind: 'image',
    role: 'product_primary',
    about: 'product:trailpack-blue',
    colour: [29, 78, 216],
    background: [236, 242, 255],
    caption: 'Front product photograph of the blue Trailpack 28L.',
    alt: 'Blue day pack with two front pockets.',
    pixelCode: 'NOVA731'
  },
  'media:trailpack-orange:hero': {
    kind: 'image',
    role: 'product_primary',
    about: 'product:trailpack-orange',
    colour: [234, 88, 12],
    background: [255, 247, 237],
    caption: 'Front product photograph of the orange Trailpack 20L.',
    alt: 'Orange compact day pack with a front pocket.',
    pixelCode: 'EMBER42'
  },
  'media:inventory:chart': {
    kind: 'chart',
    role: 'inventory_summary',
    about: 'catalog',
    caption: 'Current stock by product.'
  },
  'media:warehouse:scene': {
    kind: 'scene',
    role: 'warehouse_map',
    about: 'warehouse:primary',
    caption: 'Machine-readable warehouse layout.'
  }
};

let crcTable;
function crc32(buffer) {
  if (!crcTable) {
    crcTable = Array.from({ length: 256 }, (_, index) => {
      let value = index;
      for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
      return value >>> 0;
    });
  }
  let crc = 0xffffffff;
  for (const byte of buffer) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data = Buffer.alloc(0)) {
  const typeBuffer = Buffer.from(type, 'ascii');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])));
  return Buffer.concat([length, typeBuffer, data, checksum]);
}

function encodePng(width, height, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const rows = Buffer.alloc(height * (1 + width * 4));
  for (let y = 0; y < height; y += 1) {
    const destination = y * (1 + width * 4);
    rows[destination] = 0;
    rgba.copy(rows, destination + 1, y * width * 4, (y + 1) * width * 4);
  }
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', deflateSync(rows, { level: 9 })),
    pngChunk('IEND')
  ]);
}

function decodePng(buffer) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (!buffer.subarray(0, 8).equals(signature)) throw new Error('Not a PNG');
  let offset = 8;
  let width;
  let height;
  const idat = [];
  while (offset < buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString('ascii', offset + 4, offset + 8);
    const data = buffer.subarray(offset + 8, offset + 8 + length);
    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      if (data[8] !== 8 || data[9] !== 6) throw new Error('Unsupported PNG format');
    }
    if (type === 'IDAT') idat.push(data);
    offset += 12 + length;
    if (type === 'IEND') break;
  }
  const rows = inflateSync(Buffer.concat(idat));
  const stride = width * 4;
  const rgba = Buffer.alloc(width * height * 4);
  let previous = Buffer.alloc(stride);
  for (let y = 0; y < height; y += 1) {
    const rowOffset = y * (stride + 1);
    const filter = rows[rowOffset];
    const raw = rows.subarray(rowOffset + 1, rowOffset + 1 + stride);
    const decoded = Buffer.alloc(stride);
    for (let index = 0; index < stride; index += 1) {
      const left = index >= 4 ? decoded[index - 4] : 0;
      const up = previous[index];
      const upperLeft = index >= 4 ? previous[index - 4] : 0;
      if (filter === 0) decoded[index] = raw[index];
      else if (filter === 1) decoded[index] = (raw[index] + left) & 255;
      else if (filter === 2) decoded[index] = (raw[index] + up) & 255;
      else if (filter === 3) decoded[index] = (raw[index] + Math.floor((left + up) / 2)) & 255;
      else if (filter === 4) {
        const p = left + up - upperLeft;
        const pa = Math.abs(p - left);
        const pb = Math.abs(p - up);
        const pc = Math.abs(p - upperLeft);
        decoded[index] = (raw[index] + (pa <= pb && pa <= pc ? left : pb <= pc ? up : upperLeft)) & 255;
      } else throw new Error(`Unsupported PNG filter ${filter}`);
    }
    decoded.copy(rgba, y * stride);
    previous = decoded;
  }
  return { width, height, rgba };
}

function setPixel(rgba, width, x, y, colour) {
  if (x < 0 || y < 0 || x >= width || y >= rgba.length / 4 / width) return;
  const offset = (y * width + x) * 4;
  rgba[offset] = colour[0];
  rgba[offset + 1] = colour[1];
  rgba[offset + 2] = colour[2];
  rgba[offset + 3] = colour[3] ?? 255;
}

function rectangle(rgba, width, x, y, w, h, colour) {
  for (let py = y; py < y + h; py += 1) {
    for (let px = x; px < x + w; px += 1) setPixel(rgba, width, px, py, colour);
  }
}

function encodePixelCode(rgba, width, code) {
  rectangle(rgba, width, PANEL.x, PANEL.y, PANEL.width, PANEL.height, [255, 255, 255]);
  rectangle(rgba, width, PANEL.x, PANEL.y, PANEL.width, 2, [20, 20, 20]);
  rectangle(rgba, width, PANEL.x, PANEL.y + PANEL.height - 2, PANEL.width, 2, [20, 20, 20]);
  rectangle(rgba, width, PANEL.x, PANEL.y, 2, PANEL.height, [20, 20, 20]);
  rectangle(rgba, width, PANEL.x + PANEL.width - 2, PANEL.y, 2, PANEL.height, [20, 20, 20]);
  for (let column = 0; column < code.length; column += 1) {
    const value = code.charCodeAt(column);
    for (let bit = 0; bit < 7; bit += 1) {
      const on = Boolean(value & (1 << (6 - bit)));
      rectangle(rgba, width, PANEL.x + 4 + column * 6, PANEL.y + 4 + bit * 6, 5, 5, on ? [8, 8, 8] : [240, 240, 240]);
    }
  }
}

function renderHero(entry) {
  const rgba = Buffer.alloc(WIDTH * HEIGHT * 4);
  rectangle(rgba, WIDTH, 0, 0, WIDTH, HEIGHT, entry.background);
  rectangle(rgba, WIDTH, 195, 45, 210, 285, entry.colour);
  rectangle(rgba, WIDTH, 175, 90, 25, 185, entry.colour.map((value) => Math.max(0, value - 25)));
  rectangle(rgba, WIDTH, 400, 90, 25, 185, entry.colour.map((value) => Math.max(0, value - 25)));
  rectangle(rgba, WIDTH, 225, 205, 150, 90, entry.colour.map((value) => Math.max(0, value - 35)));
  rectangle(rgba, WIDTH, 285, 65, 30, 8, [245, 245, 245]);
  rectangle(rgba, WIDTH, 286, 220, 28, 6, [245, 245, 245]);
  encodePixelCode(rgba, WIDTH, entry.pixelCode);
  return encodePng(WIDTH, HEIGHT, rgba);
}

function crop(buffer, region) {
  const image = decodePng(buffer);
  const { x, y, width, height } = region;
  if (![x, y, width, height].every(Number.isInteger) || x < 0 || y < 0 || width < 1 || height < 1 || x + width > image.width || y + height > image.height) {
    throw new HttpError(400, 'INVALID_REGION', 'Region must be an in-bounds integer rectangle');
  }
  if (width * height > 2_000_000) throw new HttpError(413, 'REGION_TOO_LARGE', 'Requested region exceeds the pixel limit');
  const rgba = Buffer.alloc(width * height * 4);
  for (let row = 0; row < height; row += 1) {
    const start = ((y + row) * image.width + x) * 4;
    image.rgba.copy(rgba, row * width * 4, start, start + width * 4);
  }
  return encodePng(width, height, rgba);
}

function parseRegion(value) {
  if (!value) return null;
  if (value === 'inspection-mark') return PANEL;
  const parts = value.split(',').map(Number);
  if (parts.length !== 4) throw new HttpError(400, 'INVALID_REGION', 'Use a named region or x,y,width,height');
  return { x: parts[0], y: parts[1], width: parts[2], height: parts[3] };
}

export class MediaRegistry {
  constructor(store) {
    this.store = store;
    this.cache = new Map();
    this.namedRegionCache = new Map();
  }

  has(id) {
    return Boolean(entries[id]);
  }

  imageBytes(id, regionValue = null) {
    const entry = entries[id];
    if (!entry) throw new HttpError(404, 'MEDIA_NOT_FOUND', `Unknown media resource: ${id}`);
    if (entry.kind !== 'image') throw new HttpError(409, 'MEDIA_HAS_NO_PIXELS', 'Use the media data endpoint for this semantic visual');
    let original = this.cache.get(id);
    if (!original) {
      original = renderHero(entry);
      this.cache.set(id, original);
    }
    const region = parseRegion(regionValue);
    if (!region) return Buffer.from(original);
    if (regionValue === 'inspection-mark') {
      const cacheKey = `${id}:${regionValue}`;
      let regionBytes = this.namedRegionCache.get(cacheKey);
      if (!regionBytes) {
        regionBytes = crop(original, region);
        this.namedRegionCache.set(cacheKey, regionBytes);
      }
      return Buffer.from(regionBytes);
    }
    return crop(original, region);
  }

  descriptor(id, origin) {
    const entry = entries[id];
    if (!entry) throw new HttpError(404, 'MEDIA_NOT_FOUND', `Unknown media resource: ${id}`);
    if (entry.kind === 'image') {
      const bytes = this.imageBytes(id);
      const inspectionMarkBytes = this.imageBytes(id, 'inspection-mark');
      return {
        id,
        kind: 'image',
        role: entry.role,
        context: { about: entry.about, caption: entry.caption, alt: entry.alt, trust: 'publisher_assertion' },
        source: {
          url: `${origin}/api/agent/v1/media/${encodeURIComponent(id)}/content`,
          mime_type: 'image/png',
          width: WIDTH,
          height: HEIGHT,
          byte_size: bytes.length,
          sha256: createHash('sha256').update(bytes).digest('hex')
        },
        regions: [{
          id: 'inspection-mark',
          selector: { type: 'FragmentSelector', conformsTo: 'https://www.w3.org/TR/media-frags/', value: `xywh=pixel:${PANEL.x},${PANEL.y},${PANEL.width},${PANEL.height}` },
          content_url: `${origin}/api/agent/v1/media/${encodeURIComponent(id)}/content?region=inspection-mark`,
          byte_size: inspectionMarkBytes.length,
          sha256: createHash('sha256').update(inspectionMarkBytes).digest('hex'),
          purpose: 'machine-readable inspection mark',
          encoding: 'ascii-7-grid-v1'
        }],
        provenance: { generator: 'agent-native-web-reference', source_kind: 'first-party-generated', integrity: 'sha256' },
        rights: { agent_input: 'allowed' },
        derived_assertions: []
      };
    }
    return {
      id,
      kind: entry.kind,
      role: entry.role,
      context: { about: entry.about, caption: entry.caption, trust: 'publisher_assertion' },
      data_url: `${origin}/api/agent/v1/media/${encodeURIComponent(id)}/data`,
      pixel_rendering_required: false
    };
  }

  data(id) {
    const entry = entries[id];
    if (!entry) throw new HttpError(404, 'MEDIA_NOT_FOUND', `Unknown media resource: ${id}`);
    if (entry.kind === 'chart') {
      const products = this.store.listProducts();
      return {
        id,
        kind: 'chart-data',
        data: products.map((product) => ({ product_id: product.id, name: product.name, stock: product.availability.stock })),
        specification: {
          grammar: 'vega-lite-like',
          mark: 'bar',
          encoding: { x: { field: 'name', type: 'nominal' }, y: { field: 'stock', type: 'quantitative' } }
        }
      };
    }
    if (entry.kind === 'scene') {
      return {
        id,
        kind: 'scene-graph',
        coordinate_system: { unit: 'metre', origin: 'south-west' },
        nodes: [
          { id: 'zone:packing', type: 'zone', bounds: [0, 0, 8, 5], label: 'Packing' },
          { id: 'rack:backpacks', type: 'rack', bounds: [10, 1, 14, 4], label: 'Backpack stock', contains: ['product:trailpack-blue', 'product:trailpack-orange'] },
          { id: 'exit:main', type: 'exit', position: [4, 8], label: 'Main exit' }
        ]
      };
    }
    throw new HttpError(409, 'MEDIA_HAS_NO_STRUCTURED_DATA', 'This image is available as direct bytes and regions');
  }
}

export function decodeInspectionMark(pngBytes) {
  const image = decodePng(pngBytes);
  if (image.width !== PANEL.width || image.height !== PANEL.height) {
    throw new Error(`Expected a ${PANEL.width}x${PANEL.height} inspection region`);
  }
  let result = '';
  for (let column = 0; column < 7; column += 1) {
    let value = 0;
    for (let bit = 0; bit < 7; bit += 1) {
      const x = 4 + column * 6 + 2;
      const y = 4 + bit * 6 + 2;
      const offset = (y * image.width + x) * 4;
      const on = image.rgba[offset] < 100;
      value = (value << 1) | Number(on);
    }
    result += String.fromCharCode(value);
  }
  return result;
}

export function mediaIds() {
  return Object.keys(entries);
}
