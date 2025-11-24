
import { Router } from 'express';
import fs from 'fs';
import path from 'path';

const router = Router();
const dataFile = path.resolve(process.cwd(), 'data', 'items.json');

function readData() {
  try {
    const raw = fs.readFileSync(dataFile, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return [];
  }
}

function writeData(data) {
  fs.writeFileSync(dataFile, JSON.stringify(data, null, 2));
}

router.get('/', (req, res) => {
  res.json(readData());
});

router.get('/:id', (req, res) => {
  const item = readData().find(x => String(x.id) === String(req.params.id));
  if (!item) return res.status(404).json({ error: 'Item not found' });
  res.json(item);
});

router.post('/', (req, res) => {
  const data = readData();
  const nextId = data.length ? Math.max(...data.map(x => Number(x.id))) + 1 : 1;
  const item = { id: nextId, ...(req.body ?? {}) };
  data.push(item);
  writeData(data);
  res.status(201).json(item);
});

router.put('/:id', (req, res) => {
  const data = readData();
  const idx = data.findIndex(x => String(x.id) === String(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Item not found' });
  data[idx] = { ...data[idx], ...req.body };
  writeData(data);
  res.json(data[idx]);
});

router.delete('/:id', (req, res) => {
  const data = readData();
  const idx = data.findIndex(x => String(x.id) === String(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Item not found' });
  const removed = data.splice(idx, 1)[0];
  writeData(data);
  res.json(removed);
});

export default router;
