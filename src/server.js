
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'supervisor_backend' });
});

// Routes
import itemsRouter from './routes/items.js';
app.use('/api/items', itemsRouter);

// 404
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, () => {
    console.log(`server running on http://localhost:${PORT}`);
    });

