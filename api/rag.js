import { neon } from '@neondatabase/serverless';

export const config = { maxDuration: 30 };

const DB_URL = process.env.POSTGRES_URL || process.env.DATABASE_URL;
if (!DB_URL) console.error('[rag] ❌ POSTGRES_URL / DATABASE_URL belum di-set!');
const sql = neon(DB_URL);

const EMBED_DIM = 384;

let schemaReady = false;
async function ensureSchema() {
  if (schemaReady) return;
  await sql`CREATE EXTENSION IF NOT EXISTS vector`;
  await sql`CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    user_key TEXT NOT NULL,
    title TEXT NOT NULL,
    content_length INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS document_chunks (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
    user_key TEXT NOT NULL,
    content TEXT NOT NULL,
    embedding vector(384),
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`;
  await sql`CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_key)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_chunks_user ON document_chunks(user_key)`;
  try {
    await sql`CREATE INDEX IF NOT EXISTS idx_chunks_embedding ON document_chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)`;
  } catch (e) {
    console.warn('[rag] ivfflat index skip:', e.message);
  }
  schemaReady = true;
}

function vecStr(emb) {
  if (!Array.isArray(emb) || emb.length !== EMBED_DIM) {
    throw new Error(`Embedding dim mismatch: ${emb?.length || 0} vs ${EMBED_DIM}`);
  }
  return '[' + emb.map(n => Number(n).toFixed(6)).join(',') + ']';
}

async function handleUpload(req, res) {
  const { userKey, title, content, chunks } = req.body || {};
  if (!userKey) return res.status(400).json({ error: 'userKey wajib' });
  if (!title || !Array.isArray(chunks) || !chunks.length) {
    return res.status(400).json({ error: 'title & chunks wajib' });
  }
  if (chunks.length > 200) {
    return res.status(400).json({ error: 'Dokumen terlalu panjang (max 200 chunk)' });
  }
  for (const c of chunks) {
    if (!c || typeof c.text !== 'string' || !Array.isArray(c.embedding)) {
      return res.status(400).json({ error: 'Format chunk salah' });
    }
    if (c.embedding.length !== EMBED_DIM) {
      return res.status(400).json({ error: `Embedding harus ${EMBED_DIM} dimensi` });
    }
  }

  const inserted = await sql`
    INSERT INTO documents (user_key, title, content_length)
    VALUES (${userKey}, ${String(title).slice(0, 200)}, ${String(content || '').length})
    RETURNING id
  `;
  const docId = inserted[0].id;

  for (const c of chunks) {
    const vec = vecStr(c.embedding);
    await sql`
      INSERT INTO document_chunks (document_id, user_key, content, embedding)
      VALUES (${docId}, ${userKey}, ${String(c.text).slice(0, 2000)}, ${vec}::vector)
    `;
  }

  return res.status(200).json({ ok: true, documentId: docId, chunks: chunks.length });
}

async function handleList(req, res) {
  const userKey = (req.query && req.query.userKey) || (req.body && req.body.userKey);
  if (!userKey) return res.status(400).json({ error: 'userKey wajib' });
  const rows = await sql`
    SELECT d.id, d.title, d.content_length, d.created_at,
           (SELECT COUNT(*) FROM document_chunks c WHERE c.document_id = d.id) AS chunk_count
    FROM documents d
    WHERE d.user_key = ${userKey}
    ORDER BY d.id DESC
  `;
  return res.status(200).json({ ok: true, documents: rows });
}

async function handleDelete(req, res) {
  const { userKey, id } = req.body || {};
  if (!userKey || !id) return res.status(400).json({ error: 'userKey & id wajib' });
  await sql`DELETE FROM documents WHERE id = ${id} AND user_key = ${userKey}`;
  return res.status(200).json({ ok: true });
}

async function handleSearch(req, res) {
  const { userKey, embedding, topK } = req.body || {};
  if (!userKey || !Array.isArray(embedding)) {
    return res.status(400).json({ error: 'userKey & embedding wajib' });
  }
  if (embedding.length !== EMBED_DIM) {
    return res.status(400).json({ error: `Embedding harus ${EMBED_DIM} dimensi` });
  }
  const k = Math.min(Math.max(parseInt(topK) || 3, 1), 10);
  const vec = vecStr(embedding);
  const rows = await sql`
    SELECT c.content, d.title,
           1 - (c.embedding <=> ${vec}::vector) AS similarity
    FROM document_chunks c
    JOIN documents d ON d.id = c.document_id
    WHERE c.user_key = ${userKey}
    ORDER BY c.embedding <=> ${vec}::vector
    LIMIT ${k}
  `;
  return res.status(200).json({ ok: true, results: rows });
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    await ensureSchema();
    const action = (req.query && req.query.action) || (req.body && req.body.action);

    if (req.method === 'GET') {
      if (action === 'list') return await handleList(req, res);
      return res.status(400).json({ error: 'Action GET tidak dikenal' });
    }

    switch (action) {
      case 'upload': return await handleUpload(req, res);
      case 'list':   return await handleList(req, res);
      case 'delete': return await handleDelete(req, res);
      case 'search': return await handleSearch(req, res);
      default:       return res.status(400).json({ error: 'Action tidak dikenal: ' + action });
    }
  } catch (err) {
    console.error('[rag] error:', err);
    return res.status(500).json({ error: err.message || 'Server error' });
  }
}
