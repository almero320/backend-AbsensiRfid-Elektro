require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const FormData = require('form-data');
const axios = require('axios');

const app = express();

// Middleware penting
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // untuk ESP32

mongoose.connect(process.env.MONGO_URL, {
  serverSelectionTimeoutMS: 30000,   // 30 detik timeout
  socketTimeoutMS: 60000,
  connectTimeoutMS: 30000,
  family: 4  // pakai IPv4 (Railway kadang IPv6 bermasalah)
})
  .then(() => {
    console.log('[DB] MongoDB connected successfully');
  })
  .catch(err => {
    console.error('[DB] MongoDB connection error:', err.message);
    console.error('[DB] Full error stack:', err.stack);
  });

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  rfid_uid: { type: String, unique: true, sparse: true },
  face_descriptor: [Number],
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  attendance: [{
    date: { type: Date, default: Date.now },
    clockIn: { type: Date },
    clockOut: { type: Date },
    status: String  // "Hadir", "Terlambat", dll (opsional)
  }],
  face_verified: { type: Boolean, default: false },
  phone: { type: String }
});

const User = mongoose.model('User', userSchema);

// Auto create admin
(async () => {
  try {
    const exists = await User.findOne({ username: 'admin' });
    if (!exists) {
      const hashed = await bcrypt.hash('admin123', 10);
      await new User({
        name: 'Administrator',
        username: 'admin',
        password: hashed,
        role: 'admin',
        rfid_uid: 'ADMIN000',
        attendance: []
      }).save();
      console.log('[INIT] Default admin created');
    }
  } catch (err) {
    console.error('[INIT] Error:', err.message);
  }
})();

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'Token tidak ada' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'rahasia123');
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token invalid' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  next();
};

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ msg: 'Username atau password salah' });
    }
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || 'rahasia123', { expiresIn: '8h' });
    res.json({ token, role: user.role, userId: user._id.toString() });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Get face descriptor
app.get('/api/user/face', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user?.face_descriptor?.length) return res.status(404).json({ msg: 'Belum ada data wajah' });
    res.json({ descriptor: user.face_descriptor });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Set face verified (untuk sesi)
app.post('/api/verify-face', auth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { face_verified: true });
    setTimeout(async () => {
      await User.findByIdAndUpdate(req.user.id, { face_verified: false });
    }, 300000); // 5 menit
    res.json({ msg: 'Wajah diverifikasi' });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Enroll user
app.post('/api/admin/enroll', auth, adminOnly, async (req, res) => {
  const { name, username, password, rfid_uid, face_descriptor } = req.body;
  try {
    if (!name || !username || !password || !Array.isArray(face_descriptor) || face_descriptor.length !== 128) {
      return res.status(400).json({ msg: 'Data tidak lengkap' });
    }
    if (await User.findOne({ username })) return res.status(400).json({ msg: 'Username sudah ada' });
    if (rfid_uid && await User.findOne({ rfid_uid: rfid_uid.toUpperCase() })) {
      return res.status(400).json({ msg: 'RFID sudah terdaftar' });
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({
      name, username, password: hashed,
      rfid_uid: rfid_uid ? rfid_uid.toUpperCase() : undefined,
      face_descriptor,
      role: 'user',
      attendance: []
    });
    await user.save();
    res.json({ msg: 'User berhasil ditambahkan' });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// List users
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const users = await User.find({}).select('-password -face_descriptor');
    res.json(users);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Delete user
app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ msg: 'User tidak ditemukan' });
    if (user.role === 'admin') return res.status(403).json({ msg: 'Tidak bisa hapus admin' });
    await User.findByIdAndDelete(req.params.id);
    res.json({ msg: 'User dihapus' });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Absen dari RFID - FIXED & ROBUST
app.get('/api/user/attendance', auth, async (req, res) => {
  try {
    console.log('[ATTENDANCE] User meminta rekap:', req.user.id);
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('[ATTENDANCE] User tidak ditemukan');
      return res.status(404).json({ msg: 'User tidak ditemukan' });
    }
    res.json({ attendance: user.attendance || [] });
  } catch (err) {
    console.error('[ATTENDANCE] Error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

app.post('/absen', async (req, res) => {
  console.log('[ABSEN] Request masuk. Body:', req.body);

  const uid = req.body.uid;
  if (!uid) {
    console.log('[ABSEN] UID tidak ada');
    return res.status(400).json({ msg: 'UID tidak ada' });
  }

  const upperUid = uid.toUpperCase().trim();
  console.log('[ABSEN] UID normalized:', upperUid);

  try {
    const user = await User.findOne({ rfid_uid: upperUid });
    if (!user) {
      console.log('[ABSEN] RFID tidak terdaftar:', upperUid);
      return res.status(404).json({ msg: 'RFID tidak terdaftar' });
    }

    console.log('[ABSEN] User ditemukan:', user.username, 'face_verified:', user.face_verified);

    if (!user.face_verified) {
      console.log('[ABSEN] Wajah belum diverifikasi');
      return res.status(403).json({ msg: 'Wajah belum diverifikasi' });
    }

    // Pastikan attendance array
    if (!Array.isArray(user.attendance)) {
      user.attendance = [];
      console.log('[ABSEN] Attendance diperbaiki menjadi array');
    }

    user.attendance.push({ date: new Date(), status: 'Hadir' });
    await user.save();
    console.log('[ABSEN] Attendance disimpan, total:', user.attendance.length);

    // Reset face_verified
    await User.findByIdAndUpdate(user._id, { face_verified: false });
    console.log('[ABSEN] face_verified direset');

    // Fonnte WA
    try {
      const data = new FormData();
      data.append('target', '6282227097005');
      data.append('message', `Absen berhasil!\nNama: ${user.name}\nWaktu: ${new Date().toLocaleString('id-ID')}`);
      await axios.post('https://api.fonnte.com/send', data, {
        headers: { ...data.getHeaders(), Authorization: process.env.FONNTE_TOKEN }
      });
      console.log('[ABSEN] WA terkirim');
    } catch (waErr) {
      console.error('[ABSEN] Fonnte WA gagal:', waErr.message);
    }

  // Route /absen - support clock in & out
app.post('/absen', async (req, res) => {
  const { uid } = req.body;
  console.log('[ABSEN] Request masuk - UID:', uid);

  if (!uid) return res.status(400).json({ msg: 'UID tidak ada' });

  const upperUid = uid.toUpperCase().trim();

  try {
    const user = await User.findOne({ rfid_uid: upperUid });
    if (!user) return res.status(404).json({ msg: 'RFID tidak terdaftar' });

    if (!user.face_verified) return res.status(403).json({ msg: 'Wajah belum diverifikasi' });

    // Cek apakah hari ini sudah clock in atau belum
    const today = new Date().setHours(0, 0, 0, 0);
    const todayAttendance = user.attendance.find(a => {
      const aDate = new Date(a.date).setHours(0, 0, 0, 0);
      return aDate === today;
    });

    let message = '';
    const now = new Date();

    if (!todayAttendance) {
      // Clock In pertama hari ini
      user.attendance.push({
        date: now,
        clockIn: now,
        status: 'Hadir'
      });
      message = 'Clock In berhasil';
      console.log('[ABSEN] Clock In:', user.username);
    } else if (!todayAttendance.clockOut) {
      // Clock Out
      todayAttendance.clockOut = now;
      message = 'Clock Out berhasil';
      console.log('[ABSEN] Clock Out:', user.username);
    } else {
      // Sudah absen 2 kali hari ini
      return res.status(400).json({ msg: 'Sudah absen masuk & keluar hari ini' });
    }

    await user.save();

    // Reset face_verified setelah absen
    await User.findByIdAndUpdate(user._id, { face_verified: false });

    // Kirim ke Google Spreadsheet
try {
  const gsData = {
    name: user.name,
    clockIn: todayAttendance ? new Date(todayAttendance.clockIn).toLocaleTimeString('id-ID') : now.toLocaleTimeString('id-ID'),
    clockOut: todayAttendance?.clockOut ? new Date(todayAttendance.clockOut).toLocaleTimeString('id-ID') : ""
  };

  await axios.post(process.env.GOOGLE_SCRIPT_URL, gsData, {
    headers: { 'Content-Type': 'application/json' }
  });
  console.log('[GS] Data absen terkirim ke spreadsheet');
} catch (gsErr) {
  console.error('[GS] Gagal kirim ke spreadsheet:', gsErr.message);
}

    // Kirim WA (opsional, tetap jalan)
    try {
      const data = new FormData();
      data.append('target', '6282227097005');
      data.append('message', `${message}!\nNama: ${user.name}\nWaktu: ${now.toLocaleString('id-ID')}`);
      await axios.post('https://api.fonnte.com/send', data, {
        headers: { ...data.getHeaders(), Authorization: process.env.FONNTE_TOKEN }
      });
    } catch (waErr) {
      console.error('[WA] Gagal kirim:', waErr.message);
    }

    res.json({ msg: message, name: user.name });
  } catch (err) {
    console.error('[ABSEN] Error:', err.message, err.stack);
    res.status(500).json({ msg: 'Server error', error: err.message });
  }
});

    // Return data terbaru untuk frontend
    console.log('[ABSEN] Sukses untuk:', user.username);
    res.json({
      msg: 'Absen sukses',
      name: user.name,
      attendance: user.attendance  // kirim riwayat terbaru
    });
  } catch (err) {
    console.error('[ABSEN] CRASH:', err.message, err.stack);
    res.status(500).json({ msg: 'Server error saat proses absen', error: err.message });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => console.log(`Server jalan di port ${PORT}`));





