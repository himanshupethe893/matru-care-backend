// server.js

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
// const fs = require('fs');
const bcrypt = require('bcrypt');

require('dotenv').config();

const app = express();
// Add this to your server.js, usually near the other API routes
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// --- Cloudinary Configuration ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});
// Middleware
const allowedOrigins = [
    'http://localhost:3000', // For local backend development
    'http://localhost:8080', // Common for Flutter web development (if applicable)
    'http://localhost:5000', // Another common local port
    'http://0.0.0.0:3000', // Replace with your actual frontend domain
    'https://your-render-app-name.onrender.com', // Replace with your actual Render app URL
    'https://your-custom-frontend-domain.com', // If you have a custom frontend domain
    // Add other specific origins as needed
];
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps, curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
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


// --- Database Connection ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    // useUnifiedTopology: true,
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
    } catch (e) {
        // Log the actual error for debugging
        console.error("JWT Verification Error:", e.message); 
        res.status(400).json({ msg: 'Token is not valid' });
    }
};


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
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }, async (err, token) => { 
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
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login', session: false }),
  (req, res) => {
    if (req.user.status) { // Existing user
        const payload = { user: { id: req.user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }, async (err, token) => {
            if (err) throw err;
            req.user.jwtToken = token;
            req.user.login_date_time = new Date();
            await req.user.save();
            res.redirect(`http://0.0.0.0:3000/auth/google/success?token=${token}`);
        });
    } else { // New user
        res.redirect(`http://0.0.0.0:3000/google-register?name=${req.user.name}&email=${req.user.email}&googleId=${req.user.googleId}`);
    }
  }
);

app.post('/api/google-register', async (req, res) => {
    const { name, email, googleId, status } = req.body;
    try {
        let user = new User({
            name,
            email,
            googleId,
            status,
            password: Math.random().toString(36).slice(-8) // Generate random password
        });
        await user.save();

        const payload = { user: { id: user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }, async (err, token) => {
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


console.log('Attempting to start server...');
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server started successfully on port ${PORT}`);
}).on('error', (err) => { // Add an error handler for listen
    console.error('Server failed to start:', err.message);
});
console.log('After app.listen call...');