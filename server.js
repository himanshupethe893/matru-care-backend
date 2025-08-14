// // server.js
// const express = require('express');
// const mongoose = require('mongoose');
// const cors = require('cors');
// const bodyParser = require('body-parser');
// const jwt = require('jsonwebtoken');
// const passport = require('passport');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const multer = require('multer');
// const path = require('path');
// const { CloudinaryStorage } = require('multer-storage-cloudinary');
// const cloudinary = require('cloudinary').v2;
// const axios = require('axios');
// const bcrypt = require('bcrypt');
// const http = require('http');
// const { Server } = require("socket.io");

// require('dotenv').config();

// const app = express();
// app.get('/health', (req, res) => {
//     res.status(200).send('OK');
// });
// const server = http.createServer(app);

// const io = new Server(server, {
//     cors: {
//         origin: "*",
//         methods: ["GET", "POST"]
//     }
// });
// // --- Cloudinary Configuration ---
// cloudinary.config({
//     cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
//     api_key: process.env.CLOUDINARY_API_KEY,
//     api_secret: process.env.CLOUDINARY_API_SECRET,
// });
// // Middleware
// const allowedOrigins = [
//     'http://localhost:3000', // For local backend development
//     'http://localhost:8080', // Common for Flutter web development (if applicable)
//     'http://localhost:5000', // Another common local port
//     'http://0.0.0.0:3000', // Replace with your actual frontend domain
//     'http://0.0.0.0',
//     'https://your-render-app-name.onrender.com', // Replace with your actual Render app URL
//     'https://your-custom-frontend-domain.com', // If you have a custom frontend domain
//     // Add other specific origins as needed
// ];
// app.use(cors({
//     origin: (origin, callback) => {
//         // Allow requests with no origin (like mobile apps, curl requests)
//         if (!origin) return callback(null, true);
//         if (allowedOrigins.indexOf(origin) === -1) {
//             const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
//             return callback(new Error(msg), false);
//         }
//         return callback(null, true);
//     },
//     methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], // Explicitly allow common methods
//     allowedHeaders: ['Content-Type', 'Authorization', 'x-auth-token'], // Explicitly allow headers, including your custom auth token
//     credentials: true, // Allow cookies and authentication headers to be sent
// }));
// app.use(bodyParser.json());
// app.use(passport.initialize());
// // app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// // NEW: Add a check to ensure the MONGO_URI is loaded
// if (!process.env.MONGO_URI) {
//     console.error('\x1b[31m%s\x1b[0m', 'FATAL ERROR: MONGO_URI is not defined in your .env file.');
//     process.exit(1); // Exit the process with a failure code
// }

// // --- Database Connection ---
// mongoose.connect(process.env.MONGO_URI, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
// }).then(() => console.log('MongoDB connected'))
//   .catch(err => console.log(err));

// // --- Mongoose Schemas (assuming they are the same as provided) ---
// const UserSchema = new mongoose.Schema({
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     password: { type: String, required: true },
//     status: { type: String, enum: ['Mother', 'Admin', 'Doctor'], required: true },
//     login_date_time: { type: Date , required: true, default: Date.now },
//     jwtToken: { type: String , default: null},
//     googleId: { type: String, unique: true, sparse: true },
// });
// const User = mongoose.model('User', UserSchema);

// const AdminDetailsSchema = new mongoose.Schema({
//     userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     contact_no: { type: Number, min: 1000000000, max: 9999999999, required: true },
//     address: {type:String, required: true},
// });
// const AdminDetails = mongoose.model('AdminDetails', AdminDetailsSchema);

// const DoctorDetailsSchema = new mongoose.Schema({
//     userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     contact_no: { type: Number, min: 1000000000, max: 9999999999, required: true },
//     hospital_clinic_name: {type:String, required: true},
//     specialization: {type:String, required: true},
//     years_of_experience: {type:Number, required: true, min: 0},
//     other_details: {type:String, required: true},
//     introduction: {type:String, required: true},
// });
// const DoctorDetails = mongoose.model('DoctorDetails', DoctorDetailsSchema);

// const MotherDetailsSchema = new mongoose.Schema({
//     userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     contact_no: { type: Number, min: 1000000000, max: 9999999999, required: true },
//     assigned_doctor: { type: mongoose.Schema.Types.ObjectId, ref: 'DoctorDetails' },
//     asha_worker_name: {type:String, required: true},
//     asha_worker_contact_no: {type:String, required: true},
//     date_of_pregnancy: {type:Date, required: true},
//     sonography_report_url: {type:String},
//     other_reports_url: {type:String},
//     disease_information: {
//         mother: { hereditary: {type:String}, non_hereditary: {type:String}},
//         father: { hereditary: {type:String}, non_hereditary: {type:String}},
//     },
// });
// const MotherDetails = mongoose.model('MotherDetails', MotherDetailsSchema);

// const CallSessionSchema = new mongoose.Schema({
//     callId: { type: String, required: true, unique: true },
//     callerId: { type: String, required: true },
//     calleeId: { type: String, required: true },
//     status: { type: String, enum: ['pending', 'answered', 'declined', 'ended'], default: 'pending' },
//     createdAt: { type: Date, default: Date.now, expires: 3600 }
// });
// const CallSession = mongoose.model('CallSession', CallSessionSchema);



// // --- File Upload (Multer) ---
// // --- UPDATED: File Upload (Multer with Cloudinary Storage for Images and PDFs) ---
// const storage = new CloudinaryStorage({
//     cloudinary: cloudinary,
//     params: {
//         folder: 'maternal_reports',
//         // Removed transformation to allow PDF uploads without forcing JPG conversion
//         public_id: (req, file) => `${file.fieldname}-${Date.now()}`,
//     },
// });



// const upload = multer({
//     storage: storage,
//     fileFilter: (req, file, cb) => {
//         console.log('File MIME Type:', file.mimetype);
//         console.log('Original File Name:', file.originalname);

//         const allowedMimeTypes = [
//             'image/jpeg',
//             'image/jpg',
//             'image/png',
//             'image/gif',
//             'image/webp',
//             'application/pdf'
//         ];

//         const allowedExtensions = [
//             '.jpg',
//             '.jpeg',
//             '.png',
//             '.gif',
//             '.webp', // Added .webp to extensions for consistency, although already in MIME types.
//             '.pdf'
//         ];

//         const isMimeTypeAllowed = allowedMimeTypes.includes(file.mimetype);
//         const isExtensionAllowed = allowedExtensions.includes(path.extname(file.originalname).toLowerCase());

//         // Change the condition from && (AND) to || (OR)
//         // This means the file is allowed if it matches by MIME type OR by extension.
//         if (isMimeTypeAllowed || isExtensionAllowed) {
//             return cb(null, true);
//         } else {
//             cb(new Error("File upload only supports image (JPG, JPEG, PNG, GIF, WebP) and PDF formats."), false);
//         }
//     }
// });


// // --- Middleware to verify token (MOVED TO BE BEFORE ITS USAGE) ---
// const auth = (req, res, next) => {
//     const token = req.header('x-auth-token');
//     if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

//     try {
//         const decoded = jwt.verify(token, process.env.JWT_SECRET);
//         req.user = decoded.user;
//         next();
//     } catch (e) {
//         // Log the actual error for debugging
//         console.error("JWT Verification Error:", e.message); 
//         res.status(400).json({ msg: 'Token is not valid' });
//     }
// };



// // --- Socket.IO Connection Logic (remains the same) ---
// io.on('connection', (socket) => {
//     console.log(`User connected: ${socket.id}`);
//     socket.on('join-room', (userId) => {
//         socket.join(userId);
//         console.log(`Socket ${socket.id} joined room for user ${userId}`);
//     });
//     socket.on('webrtc-offer', (data) => {
//         io.to(data.calleeId).emit('webrtc-offer', { offer: data.offer, callerSocketId: socket.id });
//     });
//     socket.on('webrtc-answer', (data) => {
//         io.to(data.callerSocketId).emit('webrtc-answer', { answer: data.answer, calleeSocketId: socket.id });
//     });
//     socket.on('webrtc-ice-candidate', (data) => {
//         io.to(data.targetSocketId).emit('webrtc-ice-candidate', { candidate: data.candidate });
//     });
//     socket.on('disconnect', () => {
//         console.log(`User disconnected: ${socket.id}`);
//     });
// });
// // --- API Routes ---

// // Auth Routes
// app.post('/api/register', async (req, res) => {
//     const { name, email, password, status } = req.body;
//     try {
//         let user = await User.findOne({ email });
//         if (user) return res.status(400).json({ msg: 'User already exists' });

//         user = new User({ name, email, password, status });
//         const salt = await bcrypt.genSalt(10);
//         user.password = await bcrypt.hash(password, salt);
//         await user.save();

//         const payload = { user: { id: user.id } };
//         // Increased token expiration for better user experience
//         jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '9M' }, async (err, token) => { 
//             if (err) throw err;
//             user.jwtToken = token;
//             user.login_date_time = new Date();
//             await user.save();
//             res.json({ token, user: { id: user.id, name: user.name, email: user.email, status: user.status } });
//         });
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server error');
//     }
// });

// app.post('/api/login', async (req, res) => {
//     const { email, password } = req.body;
//     try {
//         let user = await User.findOne({ email });
//         if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

//         const isMatch = await bcrypt.compare(password, user.password);
//         if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

//         const payload = { user: { id: user.id } };
//         // Increased token expiration for better user experience
//         jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }, async (err, token) => { 
//             if (err) throw err;
//             user.jwtToken = token;
//             user.login_date_time = new Date();
//             await user.save();
//             res.json({ token, user: { id: user.id, name: user.name, email: user.email, status: user.status } });
//         });
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server error');
//     }
// });

// app.post('/api/logout', auth, async (req, res) => {
//     try {
//         // Get the user ID from the authenticated token (req.user.id), not the request body
//         await User.findByIdAndUpdate(req.user.id, { $unset: { jwtToken: "" } });
//         res.json({ msg: 'Logged out successfully' });
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server error');
//     }
// });

// // Google Auth Routes
// app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login', session: false }),
//   (req, res) => {
//     if (req.user.status) { // Existing user
//         const payload = { user: { id: req.user.id } };
//         jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }, async (err, token) => {
//             if (err) throw err;
//             req.user.jwtToken = token;
//             req.user.login_date_time = new Date();
//             await req.user.save();
//             res.redirect(`http://0.0.0.0:3000/auth/google/success?token=${token}`);
//         });
//     } else { // New user
//         res.redirect(`http://0.0.0.0:3000/google-register?name=${req.user.name}&email=${req.user.email}&googleId=${req.user.googleId}`);
//     }
//   }
// );

// app.post('/api/google-register', async (req, res) => {
//     const { name, email, googleId, status } = req.body;
//     try {
//         let user = new User({
//             name,
//             email,
//             googleId,
//             status,
//             password: Math.random().toString(36).slice(-8) // Generate random password
//         });
//         await user.save();

//         const payload = { user: { id: user.id } };
//         jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }, async (err, token) => {
//             if (err) throw err;
//             user.jwtToken = token;
//             user.login_date_time = new Date();
//             await user.save();
//             res.json({ token, user: { id: user.id, name: user.name, email: user.email, status: user.status } });
//         });
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server error');
//     }
// });


// // Details Routes
// app.post('/api/details/admin', auth, upload.none(), async (req, res) => {
//     const { contact_no, address } = req.body;
//     try {
//         const user = await User.findById(req.user.id);
//         let details = await AdminDetails.findOne({ userId: req.user.id });
//         if (details) {
//             details.contact_no = contact_no;
//             details.address = address;
//         } else {
//             details = new AdminDetails({
//                 userId: req.user.id,
//                 name: user.name,
//                 email: user.email,
//                 contact_no,
//                 address
//             });
//         }
//         await details.save();
//         res.json(details);
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });

// app.get('/api/details/admin', auth, async (req, res) => {
//     try {
//         const details = await AdminDetails.findOne({ userId: req.user.id });
//         if (!details) return res.status(404).json({ msg: 'Details not found' });
//         res.json(details);
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });

// app.post('/api/details/doctor', auth, upload.none(), async (req, res) => {
//     const { contact_no, hospital_clinic_name, specialization, years_of_experience, other_details, introduction } = req.body;
//     try {
//         const user = await User.findById(req.user.id);
//         let details = await DoctorDetails.findOne({ userId: req.user.id });
//         if (details) {
//             details.contact_no = contact_no;
//             details.hospital_clinic_name = hospital_clinic_name;
//             details.specialization = specialization;
//             details.years_of_experience = years_of_experience;
//             details.other_details = other_details;
//             details.introduction = introduction;
//         } else {
//             details = new DoctorDetails({
//                 userId: req.user.id,
//                 name: user.name,
//                 email: user.email,
//                 contact_no, hospital_clinic_name, specialization, years_of_experience, other_details, introduction
//             });
//         }
//         await details.save();
//         res.json(details);
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });

// app.get('/api/details/doctor', auth, async (req, res) => {
//     try {
//         const details = await DoctorDetails.findOne({ userId: req.user.id });
//         if (!details) return res.status(404).json({ msg: 'Details not found' });
//         res.json(details);
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });

// // NEW: Route for a doctor to get their assigned patients
// app.get('/api/doctor/patients', auth, async (req, res) => {
//     try {
//         // 1. Find the doctor's details to get their DoctorDetails _id
//         const doctor = await DoctorDetails.findOne({ userId: req.user.id });
//         if (!doctor) {
//             return res.status(404).json({ msg: 'Doctor details not found for this user.' });
//         }

//         // 2. Find all mothers (patients) assigned to this doctor
//         const patients = await MotherDetails.find({ assigned_doctor: doctor._id })
//                                             .select('name email userId'); // Select the fields you want to return

//         res.json(patients);
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });


// app.get('/api/doctors', auth, async (req, res) => {
//     try {
//         // Assuming 'name' is the field you want to select from DoctorDetails
//         // If 'name_id' is a specific field on the DoctorDetails schema, keep it.
//         // Otherwise, it should be just 'name' or any other field you want to return.
//         const doctors = await DoctorDetails.find().select('name _id'); // Select name and _id
//         res.json(doctors);
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });


// app.post('/api/details/mother', auth, upload.fields([{ name: 'sonography_report', maxCount: 1 }, { name: 'other_reports', maxCount: 1 }]), async (req, res) => {
//     const { contact_no, assigned_doctor, asha_worker_name, asha_worker_contact_no, date_of_pregnancy, disease_information } = req.body;
//     try {
//         const user = await User.findById(req.user.id);
//         let details = await MotherDetails.findOne({ userId: req.user.id });

//         const sonography_report_url = req.files['sonography_report'] ? req.files['sonography_report'][0].path : (details ? details.sonography_report_url : undefined);
//         const other_reports_url = req.files['other_reports'] ? req.files['other_reports'][0].path : (details ? details.other_reports_url : undefined);

//         if (details) {
//             details.contact_no = contact_no;
//             details.assigned_doctor = assigned_doctor;
//             details.asha_worker_name = asha_worker_name;
//             details.asha_worker_contact_no = asha_worker_contact_no;
//             details.date_of_pregnancy = date_of_pregnancy;
//             details.sonography_report_url = sonography_report_url;
//             details.other_reports_url = other_reports_url;
//             details.disease_information = JSON.parse(disease_information);
//         } else {
//             details = new MotherDetails({
//                 userId: req.user.id,
//                 name: user.name,
//                 email: user.email,
//                 contact_no, assigned_doctor, asha_worker_name, asha_worker_contact_no, date_of_pregnancy,
//                 sonography_report_url, other_reports_url,
//                 disease_information: JSON.parse(disease_information)
//             });
//         }
//         await details.save();
//         res.json(details);
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });


// // GET route for mother details remains the same
// app.get('/api/details/mother', auth, async (req, res) => {
//     try {
//         const details = await MotherDetails.findOne({ userId: req.user.id }).populate('assigned_doctor', 'name');
//         if (!details) return res.status(404).json({ msg: 'Details not found' });
//         res.json(details);
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });

// // REVISED: Generic route for any user to initiate a call
// app.post('/api/call/initiate', auth, async (req, res) => {
//     const { calleeId } = req.body;
//     const callerId = req.user.id; // Get caller's ID from the authenticated token

//     if (!calleeId) {
//         return res.status(400).json({ msg: 'Callee ID is required' });
//     }

//     try {
//         // Create a unique but consistent call ID regardless of who calls whom
//         const participants = [callerId, calleeId].sort();
//         const callId = `call_${participants[0]}_${participants[1]}`;

//         // Create or update a call session
//         await CallSession.findOneAndUpdate(
//             { callId },
//             { callerId, calleeId, status: 'pending' },
//             { new: true, upsert: true }
//         );

//         // Fetch caller's details to send their name with the notification
//         const caller = await User.findOne({userId: callerId}).select('name');

//         // Notify the callee that there's an incoming call
//         io.to(calleeId).emit('incoming-call', {
//             callId,
//             callerId,
//             callerName: caller ? caller.name : 'Unknown Caller'
//         });

//         res.status(200).json({ msg: 'Call initiated', callId });
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });

// // NEW: Route for a patient to get their assigned doctor's details
// app.get('/api/mother/doctor', auth, async (req, res) => {
//     try {
//         const motherDetails = await MotherDetails.findOne({ userId: req.user.id })
//                                                  .populate({
//                                                      path: 'assigned_doctor',
//                                                      select: 'userId name'
//                                                  }); // Populate doctor's userId and name

//         if (!motherDetails || !motherDetails.assigned_doctor) {
//             return res.status(404).json({ msg: 'No assigned doctor found.' });
//         }
        
//         // Return only the doctor's information
//         res.json(motherDetails.assigned_doctor);
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });

// app.get('/api/doctor/patients', auth, async (req, res) => {
//     try {
//         const doctor = await DoctorDetails.findOne({ userId: req.user.id });
//         if (!doctor) {
//             return res.status(404).json({ msg: 'Doctor details not found.' });
//         }
//         const patients = await MotherDetails.find({ assigned_doctor: doctor._id })
//                                             .select('userId name email');
//         res.json(patients);
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server Error');
//     }
// });

// console.log('Attempting to start server...');
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => {
//     console.log(`Server started successfully on port ${PORT}`);
// }).on('error', (err) => { // Add an error handler for listen
//     console.error('Server failed to start:', err.message);
// });
// console.log('After app.listen call...');
// // NEW: Route for searching YouTube videos
// app.get('/api/Youtube', auth, async (req, res) => {
//     const { q: searchQuery } = req.query; // Get search query from request

//     if (!searchQuery) {
//         return res.status(400).json({ msg: 'A search query is required.' });
//     }

//     const apiKey = process.env.YOUTUBE_API_KEY;
//     const url = `https://www.googleapis.com/youtube/v3/search?part=snippet&q=${encodeURIComponent(searchQuery)}&key=${apiKey}&type=video&maxResults=15`;

//     try {
//         const response = await axios.get(url);
        
//         // Map the complex YouTube API response to a simple format
//         const videos = response.data.items.map(item => ({
//             videoId: item.id.videoId,
//             title: item.snippet.title,
//             channel: item.snippet.channelTitle,
//             thumbnailUrl: item.snippet.thumbnails.high.url,
//         }));

//         res.json(videos);

//     } catch (error) {
//         console.error('YouTube API Error:', error.response ? error.response.data : error.message);
//         res.status(500).send('Error fetching videos from YouTube.');
//     }
// });

// server.js////////////////////////////////////////////////////////////////////////////////
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer = require('multer');
const path = require('path');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;
const axios = require('axios');
const bcrypt = require('bcrypt');
const http = require('http');
const { Server } = require("socket.io");
const crypto = require('crypto');

require('dotenv').config();

// --- NEW: Encryption Setup ---
// Ensure you have a 32-byte (256-bit) key in your .env file.
// Example: ENCRYPTION_KEY=abcdefghijklmnopqrstuvwxyz123456
const algorithm = 'aes-256-cbc';
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'utf8');

// Encryption function
function encrypt(text) {
    // Generate a random 16-byte initialization vector (IV) for each encryption
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    // Prepend the IV to the encrypted text (separated by a colon)
    // This is crucial for decryption
    return iv.toString('hex') + ':' + encrypted;
}

// Decryption function
function decrypt(text) {
    try {
        const parts = text.split(':');
        // The first part is the IV, the second is the encrypted data
        const iv = Buffer.from(parts.shift(), 'hex');
        const encryptedText = Buffer.from(parts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error("Decryption failed:", error.message);
        // Return the original text or an error message if decryption fails
        return text; 
    }
}

const app = express();
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
// --- Cloudinary Configuration ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});
// Middleware
// const allowedOrigins = [
//     'http://localhost:3000', // For local backend development
//     'http://localhost:8080', // Common for Flutter web development (if applicable)
//     'http://localhost:5000', // Another common local port
//     'http://0.0.0.0:3000', // Replace with your actual frontend domain
//     'http://0.0.0.0',
//     'https://your-render-app-name.onrender.com', // Replace with your actual Render app URL
//     'https://your-custom-frontend-domain.com', // If you have a custom frontend domain
//     'null'//local testing // Add other specific origins as needed
// ];
const allowedOrigins = process.env.CORS_ORIGINS 
    ? process.env.CORS_ORIGINS.split(',') 
    : [];

console.log('Allowed CORS Origins:', allowedOrigins);
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps, curl requests)
        if (!origin || allowedOrigins.indexOf(origin) === -1) return callback(null, true);
        // if (allowedOrigins.indexOf(origin) === -1) {
        //     const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
        //     return callback(new Error(msg), false);
        // }
        else{
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], // Explicitly allow common methods
    allowedHeaders: ['Content-Type', 'Authorization', 'x-auth-token'], // Explicitly allow headers, including your custom auth token
    credentials: true, // Allow cookies and authentication headers to be sent
}));
app.use(bodyParser.json());
app.use(passport.initialize());
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// NEW: Add a check to ensure the MONGO_URI is loaded
if (!process.env.MONGO_URI) {
    console.error('\x1b[31m%s\x1b[0m', 'FATAL ERROR: MONGO_URI is not defined in your .env file.');
    process.exit(1); // Exit the process with a failure code
}

if (!process.env.ENCRYPTION_KEY || process.env.ENCRYPTION_KEY.length !== 32) {
    console.error('\x1b[31m%s\x1b[0m', 'FATAL ERROR: ENCRYPTION_KEY is not defined in your .env file or is not 32 characters long.');
    process.exit(1);
}

// --- Database Connection ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// --- Mongoose Schemas (assuming they are the same as provided) ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    status: { type: String, enum: ['Mother', 'Admin', 'Doctor'], required: true },
    login_date_time: { type: Date , required: true, default: Date.now },
    jwtToken: { type: String , default: null},
    googleId: { type: String, unique: true, sparse: true },
});
const User = mongoose.model('User', UserSchema);

const AdminDetailsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    contact_no: { type: Number, min: 1000000000, max: 9999999999, required: true },
    address: {type:String, required: true},
});
const AdminDetails = mongoose.model('AdminDetails', AdminDetailsSchema);

const DoctorDetailsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    contact_no: { type: Number, min: 1000000000, max: 9999999999, required: true },
    hospital_clinic_name: {type:String, required: true},
    specialization: {type:String, required: true},
    years_of_experience: {type:Number, required: true, min: 0},
    other_details: {type:String, required: true},
    introduction: {type:String, required: true},
});
const DoctorDetails = mongoose.model('DoctorDetails', DoctorDetailsSchema);

const MotherDetailsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    contact_no: { type: Number, min: 1000000000, max: 9999999999, required: true },
    assigned_doctor: { type: mongoose.Schema.Types.ObjectId, ref: 'DoctorDetails' },
    asha_worker_name: {type:String, required: true},
    asha_worker_contact_no: {type:String, required: true},
    date_of_pregnancy: {type:Date, required: true},
    sonography_report_url: {type:String},
    other_reports_url: {type:String},
    disease_information: {
        mother: { hereditary: {type:String}, non_hereditary: {type:String}},
        father: { hereditary: {type:String}, non_hereditary: {type:String}},
    },
});
const MotherDetails = mongoose.model('MotherDetails', MotherDetailsSchema);

const CallSessionSchema = new mongoose.Schema({
    callId: { type: String, required: true, unique: true },
    callerId: { type: String, required: true },
    calleeId: { type: String, required: true },
    status: { type: String, enum: ['pending', 'answered', 'declined', 'ended'], default: 'pending' },
    createdAt: { type: Date, default: Date.now, expires: 3600 }
});
const CallSession = mongoose.model('CallSession', CallSessionSchema);

// --- NEW: Mongoose Schemas for Chat ---
const ChatMessageSchema = new mongoose.Schema({
    conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'ChatConversation', required: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    message: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
});
const ChatMessage = mongoose.model('ChatMessage', ChatMessageSchema);

const ChatConversationSchema = new mongoose.Schema({
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
    lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'ChatMessage' },
}, { timestamps: true });
const ChatConversation = mongoose.model('ChatConversation', ChatConversationSchema);

// --- File Upload (Multer) ---
// --- UPDATED: File Upload (Multer with Cloudinary Storage for Images and PDFs) ---
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'maternal_reports',
        // Removed transformation to allow PDF uploads without forcing JPG conversion
        public_id: (req, file) => `${file.fieldname}-${Date.now()}`,
    },
});



const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        console.log('File MIME Type:', file.mimetype);
        console.log('Original File Name:', file.originalname);

        const allowedMimeTypes = [
            'image/jpeg',
            'image/jpg',
            'image/png',
            'image/gif',
            'image/webp',
            'application/pdf'
        ];

        const allowedExtensions = [
            '.jpg',
            '.jpeg',
            '.png',
            '.gif',
            '.webp', // Added .webp to extensions for consistency, although already in MIME types.
            '.pdf'
        ];

        const isMimeTypeAllowed = allowedMimeTypes.includes(file.mimetype);
        const isExtensionAllowed = allowedExtensions.includes(path.extname(file.originalname).toLowerCase());

        // Change the condition from && (AND) to || (OR)
        // This means the file is allowed if it matches by MIME type OR by extension.
        if (isMimeTypeAllowed || isExtensionAllowed) {
            return cb(null, true);
        } else {
            cb(new Error("File upload only supports image (JPG, JPEG, PNG, GIF, WebP) and PDF formats."), false);
        }
    }
});


// --- Middleware to verify token (MOVED TO BE BEFORE ITS USAGE) ---
const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
        console.log("JWT Verification");
    } catch (e) {
        // Log the actual error for debugging
        console.error("JWT Verification Error:", e.message); 
        res.status(400).json({ msg: 'Token is not valid' });
    }
};



// --- Socket.IO Connection Logic (remains the same) ---
io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);
    socket.on('join-room', (userId) => {
        socket.join(userId);
        console.log(`Socket ${socket.id} joined room for user ${userId}`);
    });
    socket.on('webrtc-offer', (data) => {
        io.to(data.calleeId).emit('webrtc-offer', { offer: data.offer, callerSocketId: socket.id });
    });
    socket.on('webrtc-answer', (data) => {
        io.to(data.callerSocketId).emit('webrtc-answer', { answer: data.answer, calleeSocketId: socket.id });
    });
    socket.on('webrtc-ice-candidate', (data) => {
        io.to(data.targetSocketId).emit('webrtc-ice-candidate', { candidate: data.candidate });
    });
    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.id}`);
    });
});
// --- API Routes ---

// Auth Routes
app.post('/api/register', async (req, res) => {
    const { name, email, password, status } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ msg: 'User already exists' });

        user = new User({ name, email, password, status });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();

        const payload = { user: { id: user.id } };
        // Increased token expiration for better user experience
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '9M' }, async (err, token) => { 
            if (err) throw err;
            user.jwtToken = token;
            user.login_date_time = new Date();
            await user.save();
            res.json({ token, user: { id: user.id, name: user.name, email: user.email, status: user.status } });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

        const payload = { user: { id: user.id } };
        // Increased token expiration for better user experience
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8d' }, async (err, token) => { 
            if (err) throw err;
            user.jwtToken = token;
            user.login_date_time = new Date();
            await user.save();
            res.json({ token, user: { id: user.id, name: user.name, email: user.email, status: user.status } });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.post('/api/logout', auth, async (req, res) => {
    try {
        // Get the user ID from the authenticated token (req.user.id), not the request body
        await User.findByIdAndUpdate(req.user.id, { $unset: { jwtToken: "" } });
        res.json({ msg: 'Logged out successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Google Auth Routes
// app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login', session: false }),
//   (req, res) => {
//     if (req.user.status) { // Existing user
//         const payload = { user: { id: req.user.id } };
//         jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }, async (err, token) => {
//             if (err) throw err;
//             req.user.jwtToken = token;
//             req.user.login_date_time = new Date();
//             await req.user.save();
//             res.redirect(`http://0.0.0.0:3000/auth/google/success?token=${token}`);
//         });
//     } else { // New user
//         res.redirect(`http://0.0.0.0:3000/google-register?name=${req.user.name}&email=${req.user.email}&googleId=${req.user.googleId}`);
//     }
//   }
// );

// app.post('/api/google-register', async (req, res) => {
//     const { name, email, googleId, status } = req.body;
//     try {
//         let user = new User({
//             name,
//             email,
//             googleId,
//             status,
//             password: Math.random().toString(36).slice(-8) // Generate random password
//         });
//         await user.save();

//         const payload = { user: { id: user.id } };
//         jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }, async (err, token) => {
//             if (err) throw err;
//             user.jwtToken = token;
//             user.login_date_time = new Date();
//             await user.save();
//             res.json({ token, user: { id: user.id, name: user.name, email: user.email, status: user.status } });
//         });
//     } catch (err) {
//         console.error(err.message);
//         res.status(500).send('Server error');
//     }
// });


// Details Routes
app.post('/api/details/admin', auth, upload.none(), async (req, res) => {
    const { contact_no, address } = req.body;
    try {
        const user = await User.findById(req.user.id);
        let details = await AdminDetails.findOne({ userId: req.user.id });
        if (details) {
            details.contact_no = contact_no;
            details.address = address;
        } else {
            details = new AdminDetails({
                userId: req.user.id,
                name: user.name,
                email: user.email,
                contact_no,
                address
            });
        }
        await details.save();
        res.json(details);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

app.get('/api/details/admin', auth, async (req, res) => {
    try {
        const details = await AdminDetails.findOne({ userId: req.user.id });
        if (!details) return res.status(404).json({ msg: 'Details not found' });
        res.json(details);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

app.post('/api/details/doctor', auth, upload.none(), async (req, res) => {
    const { contact_no, hospital_clinic_name, specialization, years_of_experience, other_details, introduction } = req.body;
    try {
        const user = await User.findById(req.user.id);
        let details = await DoctorDetails.findOne({ userId: req.user.id });
        if (details) {
            details.contact_no = contact_no;
            details.hospital_clinic_name = hospital_clinic_name;
            details.specialization = specialization;
            details.years_of_experience = years_of_experience;
            details.other_details = other_details;
            details.introduction = introduction;
        } else {
            details = new DoctorDetails({
                userId: req.user.id,
                name: user.name,
                email: user.email,
                contact_no, hospital_clinic_name, specialization, years_of_experience, other_details, introduction
            });
        }
        await details.save();
        res.json(details);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

app.get('/api/details/doctor', auth, async (req, res) => {
    try {
        const details = await DoctorDetails.findOne({ userId: req.user.id });
        if (!details) return res.status(404).json({ msg: 'Details not found' });
        res.json(details);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// NEW: Route for a doctor to get their assigned patients
app.get('/api/doctor/patients', auth, async (req, res) => {
    try {
        // 1. Find the doctor's details to get their DoctorDetails _id
        const doctor = await DoctorDetails.findOne({ userId: req.user.id });
        if (!doctor) {
            return res.status(404).json({ msg: 'Doctor details not found for this user.' });
        }

        // 2. Find all mothers (patients) assigned to this doctor
        const patients = await MotherDetails.find({ assigned_doctor: doctor._id })
                                            .select('name email userId'); // Select the fields you want to return

        res.json(patients);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


app.get('/api/doctors', auth, async (req, res) => {
    try {
        // Assuming 'name' is the field you want to select from DoctorDetails
        // If 'name_id' is a specific field on the DoctorDetails schema, keep it.
        // Otherwise, it should be just 'name' or any other field you want to return.
        const doctors = await DoctorDetails.find().select('name _id'); // Select name and _id
        res.json(doctors);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


app.post('/api/details/mother', auth, upload.fields([{ name: 'sonography_report', maxCount: 1 }, { name: 'other_reports', maxCount: 1 }]), async (req, res) => {
    const { contact_no, assigned_doctor, asha_worker_name, asha_worker_contact_no, date_of_pregnancy, disease_information } = req.body;
    try {
        const user = await User.findById(req.user.id);
        let details = await MotherDetails.findOne({ userId: req.user.id });

        const sonography_report_url = req.files['sonography_report'] ? req.files['sonography_report'][0].path : (details ? details.sonography_report_url : undefined);
        const other_reports_url = req.files['other_reports'] ? req.files['other_reports'][0].path : (details ? details.other_reports_url : undefined);

        if (details) {
            details.contact_no = contact_no;
            details.assigned_doctor = assigned_doctor;
            details.asha_worker_name = asha_worker_name;
            details.asha_worker_contact_no = asha_worker_contact_no;
            details.date_of_pregnancy = date_of_pregnancy;
            details.sonography_report_url = sonography_report_url;
            details.other_reports_url = other_reports_url;
            details.disease_information = JSON.parse(disease_information);
        } else {
            details = new MotherDetails({
                userId: req.user.id,
                name: user.name,
                email: user.email,
                contact_no, assigned_doctor, asha_worker_name, asha_worker_contact_no, date_of_pregnancy,
                sonography_report_url, other_reports_url,
                disease_information: JSON.parse(disease_information)
            });
        }
        await details.save();
        res.json(details);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


// GET route for mother details remains the same
app.get('/api/details/mother', auth, async (req, res) => {
    try {
        const details = await MotherDetails.findOne({ userId: req.user.id }).populate('assigned_doctor', 'name');
        if (!details) return res.status(404).json({ msg: 'Details not found' });
        res.json(details);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// REVISED: Generic route for any user to initiate a call
app.post('/api/call/initiate', auth, async (req, res) => {
    const { calleeId } = req.body;
    const callerId = req.user.id; // Get caller's ID from the authenticated token

    if (!calleeId) {
        return res.status(400).json({ msg: 'Callee ID is required' });
    }

    try {
        // Create a unique but consistent call ID regardless of who calls whom
        const participants = [callerId, calleeId].sort();
        const callId = `call_${participants[0]}_${participants[1]}`;

        // Create or update a call session
        await CallSession.findOneAndUpdate(
            { callId },
            { callerId, calleeId, status: 'pending' },
            { new: true, upsert: true }
        );

        // Fetch caller's details to send their name with the notification
        const caller = await User.findById(callerId).select('name');

        // Notify the callee that there's an incoming call
        io.to(calleeId).emit('incoming-call', {
            callId,
            callerId,
            callerName: caller ? caller.name : 'Unknown Caller'
        });

        res.status(200).json({ msg: 'Call initiated', callId });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// NEW: Route for a patient to get their assigned doctor's details
app.get('/api/mother/doctor', auth, async (req, res) => {
    try {
        const motherDetails = await MotherDetails.findOne({ userId: req.user.id })
                                                 .populate({
                                                     path: 'assigned_doctor',
                                                     select: 'userId name'
                                                 }); // Populate doctor's userId and name

        if (!motherDetails || !motherDetails.assigned_doctor) {
            return res.status(404).json({ msg: 'No assigned doctor found.' });
        }
        
        // Return only the doctor's information
        res.json(motherDetails.assigned_doctor);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

app.get('/api/doctor/patients', auth, async (req, res) => {
    try {
        const doctor = await DoctorDetails.findOne({ userId: req.user.id });
        if (!doctor) {
            return res.status(404).json({ msg: 'Doctor details not found.' });
        }
        const patients = await MotherDetails.find({ assigned_doctor: doctor._id })
                                            .select('userId name email');
        res.json(patients);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

console.log('Attempting to start server...');
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server started successfully on port ${PORT}`);
}).on('error', (err) => { // Add an error handler for listen
    console.error('Server failed to start:', err.message);
});
console.log('After app.listen call...');


// --- NEW: Chat Routes ---
app.post('/api/chat/send', auth, async (req, res) => {
    const { receiverId, message } = req.body;
    const senderId = req.user.id;

    try {
        let conversation = await ChatConversation.findOne({
            participants: { $all: [senderId, receiverId] },
        });

        if (!conversation) {
            conversation = new ChatConversation({
                participants: [senderId, receiverId],
            });
        }

        // NEW: Encrypt the message before saving
        const encryptedMessage = encrypt(message);

        const chatMessage = new ChatMessage({
            conversationId: conversation._id,
            sender: senderId,
            receiver: receiverId,
            message: encryptedMessage,
        });

        conversation.lastMessage = chatMessage._id;

        await Promise.all([chatMessage.save(), conversation.save()]);

        // Emit the message to the receiver's room
        io.to(receiverId).emit('receive-chat-message', {
            sender: senderId,
            message,
            timestamp: chatMessage.timestamp,
        });

        res.status(201).json(chatMessage);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

app.get('/api/chat/history/:userId', auth, async (req, res) => {
    const loggedInUserId = req.user.id;
    const otherUserId = req.params.userId;

    try {
        const conversation = await ChatConversation.findOne({
            participants: { $all: [loggedInUserId, otherUserId] },
        });

        if (!conversation) {
            return res.json([]);
        }

        const messages = await ChatMessage.find({ conversationId: conversation._id })
            .sort({ timestamp: 1 })
            .populate('sender', 'name')
            .populate('receiver', 'name');
        
        // NEW: Decrypt messages before sending// NEW: Decrypt each message before sending it to the client
        const decryptedMessages = messages.map(msg => {
            const messageObject = msg.toObject(); // Convert Mongoose document to plain object
            messageObject.message = decrypt(messageObject.message);
            return messageObject;
        });
        res.json(decryptedMessages);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


// NEW: Route to get WebRTC ICE server configuration (STUN/TURN)
app.get('/api/webrtc/ice-servers', auth, (req, res) => {
    try {
        // WebRTC requires the password key to be named 'credential'
        const iceServers = [
            {
                urls: process.env.TURN_SERVER_URL,
                username: process.env.TURN_SERVER_USERNAME,
                credential: process.env.TURN_SERVER_PASSWORD
            },
            // You can add public STUN servers as well, they are free and help find direct paths
            { urls: "stun:stun.l.google.com:19302" },
            { urls: "stun:stun1.l.google.com:19302" }
        ];

        res.json(iceServers);

    } catch (error) {
        console.error('Error fetching ICE server configuration:', error);
        res.status(500).send('Server Error');
    }
});






// NEW: Route for searching YouTube videos
app.get('/api/Youtube', auth, async (req, res) => {
    const { q: searchQuery } = req.query; // Get search query from request

    if (!searchQuery) {
        return res.status(400).json({ msg: 'A search query is required.' });
    }

    const apiKey = process.env.YOUTUBE_API_KEY;
    const url = `https://www.googleapis.com/youtube/v3/search?part=snippet&q=${encodeURIComponent(searchQuery)}&key=${apiKey}&type=video&maxResults=15`;

    try {
        const response = await axios.get(url);
        
        // Map the complex YouTube API response to a simple format
        const videos = response.data.items.map(item => ({
            videoId: item.id.videoId,
            title: item.snippet.title,
            channel: item.snippet.channelTitle,
            thumbnailUrl: item.snippet.thumbnails.high.url,
        }));

        res.json(videos);

    } catch (error) {
        console.error('YouTube API Error:', error.response ? error.response.data : error.message);
        res.status(500).send('Error fetching videos from YouTube.');
    }
});

