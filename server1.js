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
// const fs = require('fs');
// const bcrypt = require('bcrypt');
// // const { upload } = require('./your-multer-config');
// // const { Storage } = require('@google-cloud/storage');

// require('dotenv').config();

// const app = express();

// // Middleware
// app.use(cors());
// app.use(bodyParser.json());
// app.use(passport.initialize());
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// // --- Database Connection ---
// mongoose.connect(process.env.MONGO_URI, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
// }).then(() => console.log('MongoDB connected'))
//   .catch(err => console.log(err));

// // --- Mongoose Schemas ---
// const UserSchema = new mongoose.Schema({
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     password: { type: String, required: true },
//     status: { type: String, enum: ['Mother', 'Admin', 'Doctor'], required: true },
//     login_date_time: { type: Date , required: true, default: Date.now },
//     jwtToken: { type: String , default: null},
//     // Add sparse: true to the googleId field
//     googleId: { type: String, unique: true, sparse: true }, // For Google OAuth
// });
// const User = mongoose.model('User', UserSchema);

// const AdminDetailsSchema = new mongoose.Schema({
//     userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     contact_no: {
//     type: Number,
//     min: 1000000000, // Minimum 10-digit number
//     max: 9999999999, // Maximum 10-digit number
//     required: true
//   },
//     address: {type:String, required: true},
// });
// const AdminDetails = mongoose.model('AdminDetails', AdminDetailsSchema);

// const DoctorDetailsSchema = new mongoose.Schema({
//     userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     contact_no: {
//     type: Number,
//     min: 1000000000, // Minimum 10-digit number
//     max: 9999999999, // Maximum 10-digit number
//     required: true
//   },
//     hospital_clinic_name: {type:String, required: true},
//     specialization: {type:String, required: true},
//     years_of_experience: {type:Number, required: true, min: 0},
//     other_details: {type:String, required: true},
//     introduction: {type:String, required: true},
//     // profile_picture_url: String, // URL to the doctor's profile picture
// });
// const DoctorDetails = mongoose.model('DoctorDetails', DoctorDetailsSchema);

// const MotherDetailsSchema = new mongoose.Schema({
//     userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     contact_no: {
//     type: Number,
//     min: 1000000000, // Minimum 10-digit number
//     max: 9999999999, // Maximum 10-digit number
//     required: true
//   },
//     assigned_doctor: { type: mongoose.Schema.Types.ObjectId, ref: 'DoctorDetails' },
//     asha_worker_name: {type:String, required: true},
//     asha_worker_contact_no: {type:String, required: true},
//     date_of_pregnancy: {type:Date, required: true},
//     sonography_report_url: {type:String, required: true},
//     other_reports_url: {type:String, required: true},
//     disease_information: {
//         mother: { hereditary: {type:String, required: true}, non_hereditary: {type:String, required: true} },
//         father: { hereditary: {type:String, required: true}, non_hereditary: {type:String, required: true} },
//     },
// });
// const MotherDetails = mongoose.model('MotherDetails', MotherDetailsSchema);


// // --- Passport.js Google OAuth2 Strategy ---
// // passport.use(new GoogleStrategy({
// //     clientID: process.env.GOOGLE_CLIENT_ID,
// //     clientSecret: process.env.GOOGLE_CLIENT_SECRET,
// //     callbackURL: "/auth/google/callback"
// //   },
// //   async (accessToken, refreshToken, profile, done) => {
// //     try {
// //         let user = await User.findOne({ googleId: profile.id });
// //         if (user) {
// //             return done(null, user);
// //         }
        
// //         user = await User.findOne({ email: profile.emails[0].value });
// //         if (user) {
// //             user.googleId = profile.id;
// //             await user.save();
// //             return done(null, user);
// //         }

// //         // For new Google users, we need to know their status (Mother, Admin, Doctor)
// //         // This will be handled on the frontend after the initial google login redirect.
// //         const newUser = {
// //             googleId: profile.id,
// //             name: profile.displayName,
// //             email: profile.emails[0].value,
// //         };
// //         return done(null, newUser);

// //     } catch (err) {
// //         return done(err, false);
// //     }
// //   }
// // ));

// // --- File Upload (Multer) ---
// // Local Storage
// const storage = multer.diskStorage({
//     destination: function (req, file, cb) {
//         const dir = 'uploads/';
//         if (!fs.existsSync(dir)){
//             fs.mkdirSync(dir);
//         }
//         cb(null, dir);
//     },
//     filename: function (req, file, cb) {
//         cb(null, Date.now() + path.extname(file.originalname)); // Appending extension
//     }
// });

// const upload = multer({ 
//     storage: storage,
//     fileFilter: (req, file, cb) => {
//         // const allowedTypes = /jpeg|jpg|png|pdf/;
//         const allowedTypes = /jpeg|jpg/;
//         const mimetype = allowedTypes.test(file.mimetype);
//         const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
//         if (mimetype && extname) {
//             return cb(null, true);
//         }
//         cb("Error: File upload only supports the following filetypes - " + allowedTypes);
//     }
// });

// /*
// // --- Google Cloud Storage (Commented Out) ---
// const gcStorage = new Storage({
//     keyFilename: path.join(__dirname, 'your-gcloud-key.json'),
//     projectId: 'your-gcloud-project-id',
// });
// const bucket = gcStorage.bucket('your-gcloud-bucket-name');

// const gcUpload = multer({
//     storage: multer.memoryStorage(),
//     limits: {
//         fileSize: 5 * 1024 * 1024, // no larger than 5mb
//     },
// });

// const uploadToGCS = (req, res, next) => {
//     if (!req.file) {
//         return next();
//     }

//     const blob = bucket.file(Date.now() + path.extname(req.file.originalname));
//     const blobStream = blob.createWriteStream({
//         resumable: false,
//     });

//     blobStream.on('error', err => {
//         next(err);
//     });

//     blobStream.on('finish', () => {
//         req.file.cloudStoragePublicUrl = `https://storage.googleapis.com/${bucket.name}/${blob.name}`;
//         next();
//     });

//     blobStream.end(req.file.buffer);
// };
// */


// // --- API Routes ---

// // Auth Routes
// app.post('/api/register', async (req, res) => {
//     const { name, email, password, status } = req.body;
//     try {
//         let user = await User.findOne({ email });
//         if (user) return res.status(400).json({ msg: 'User already exists' });

//         user = new User({ name, email, password, status });
//         // In a real app, you'd hash the password
//         const salt = await bcrypt.genSalt(10);/////////
//         user.password = await bcrypt.hash(password, salt); ////////
//         await user.save();

//         const payload = { user: { id: user.id } };
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

//         // In a real app, you'd compare the hashed password
//         const isMatch = await bcrypt.compare(password, user.password);
//         // const isMatch = password === user.password; // Plain text comparison
//         if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

//         const payload = { user: { id: user.id } };
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

// app.post('/api/logout', auth, async (req, res) => {
//     try {
//         // Get the user ID from the authenticated token, not the request body
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
//     // On success, we need to handle what happens.
//     // If the user exists, we create a JWT and send them on their way.
//     // If it's a new user, we need them to select a status.
//     if (req.user.status) { // Existing user
//         const payload = { user: { id: req.user.id } };
//         jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '9M' }, async (err, token) => {
//             if (err) throw err;
//             req.user.jwtToken = token;
//             req.user.login_date_time = new Date();
//             await req.user.save();
//             // Redirect to a frontend route with the token
//             res.redirect(`http://0.0.0.0:3000/auth/google/success?token=${token}`);
//         });
//     } else { // New user
//         // Redirect to a frontend route for status selection
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


// // Middleware to verify token
// const auth = (req, res, next) => {
//     const token = req.header('x-auth-token');
//     if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

//     try {
//         const decoded = jwt.verify(token, process.env.JWT_SECRET);
//         req.user = decoded.user;
//         next();
//     } catch (e) {
//         res.status(400).json({ msg: 'Token is not valid' });
//     }
// };

// // Details Routes
// // Around line 338
// // app.post('/api/details/admin', auth, async (req, res) => {
// //     const { contact_no, address } = req.body;
// //     try {
// //         const user = await User.findById(req.user.id);
// //         let details = await AdminDetails.findOne({ userId: req.user.id });
// //         if (details) {
// //             details.contact_no = contact_no;
// //             details.address = address;
// //         } else {
// //             details = new AdminDetails({
// //                 userId: req.user.id,
// //                 name: user.name,
// //                 email: user.email,
// //                 contact_no,
// //                 address
// //             });
// //         }
// //         await details.save();
// //         res.json(details);
// //     } catch (err) {
// //         console.error(err.message);
// //         res.status(500).send('Server Error');
// //     }
// // });
// app.post('/api/details/admin', auth, upload.none(), async (req, res) => {
//     const { contact_no, address } = req.body; // req.body will now be populated
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

// // app.post('/api/details/doctor', auth, async (req, res) => {
// //     const { contact_no, hospital_clinic_name, specialization, years_of_experience, other_details, introduction } = req.body;
// //     try {
// //         const user = await User.findById(req.user.id);
// //         let details = await DoctorDetails.findOne({ userId: req.user.id });
// //         if (details) {
// //             details.contact_no = contact_no;
// //             details.hospital_clinic_name = hospital_clinic_name;
// //             details.specialization = specialization;
// //             details.years_of_experience = years_of_experience;
// //             details.other_details = other_details;
// //             details.introduction = introduction;
// //         } else {
// //             details = new DoctorDetails({
// //                 userId: req.user.id,
// //                 name: user.name,
// //                 email: user.email,
// //                 contact_no, hospital_clinic_name, specialization, years_of_experience, other_details, introduction
// //             });
// //         }
// //         await details.save();
// //         res.json(details);
// //     } catch (err) {
// //         console.error(err.message);
// //         res.status(500).send('Server Error');
// //     }
// // });

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

// app.get('/api/doctors', auth, async (req, res) => {
//     try {
//         const doctors = await DoctorDetails.find().select('name_id');
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

//         const sonography_report_url = req.files['sonography_report'] ? `/uploads/${req.files['sonography_report'][0].filename}` : (details ? details.sonography_report_url : undefined);
//         const other_reports_url = req.files['other_reports'] ? `/uploads/${req.files['other_reports'][0].filename}` : (details ? details.other_reports_url : undefined);

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


// const PORT = process.env.PORT || 3000;
// app.listen(PORT, '0.0.0.0', () => console.log(`Server started on port ${PORT}`));
// // Export the app for testing purposes
// module.exports = app;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// server.js

// const express = require('express');
// const mongoose = require('mongoose');
// const cors = require('cors');
// const bodyParser = require('body-parser');
// const jwt = require('jsonwebtoken');
// const passport = require('passport');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const multer = require('multer');
// const path = require('path');
// const fs = require('fs');
// const bcrypt = require('bcrypt');
// // const { upload } = require('./your-multer-config');
// // const { Storage } = require('@google-cloud/storage');

// require('dotenv').config();

// const app = express();

// // Middleware
// app.use(cors());
// app.use(bodyParser.json());
// app.use(passport.initialize());
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// // --- Database Connection ---
// mongoose.connect(process.env.MONGO_URI, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
// }).then(() => console.log('MongoDB connected'))
//   .catch(err => console.log(err));

// // --- Mongoose Schemas ---
// const UserSchema = new mongoose.Schema({
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     password: { type: String, required: true },
//     status: { type: String, enum: ['Mother', 'Admin', 'Doctor'], required: true },
//     login_date_time: { type: Date , required: true, default: Date.now },
//     jwtToken: { type: String , default: null},
//     // Add sparse: true to the googleId field
//     googleId: { type: String, unique: true, sparse: true }, // For Google OAuth
// });
// const User = mongoose.model('User', UserSchema);

// const AdminDetailsSchema = new mongoose.Schema({
//     userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     contact_no: {
//     type: Number,
//     min: 1000000000, // Minimum 10-digit number
//     max: 9999999999, // Maximum 10-digit number
//     required: true
//   },
//     address: {type:String, required: true},
// });
// const AdminDetails = mongoose.model('AdminDetails', AdminDetailsSchema);

// const DoctorDetailsSchema = new mongoose.Schema({
//     userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     contact_no: {
//     type: Number,
//     min: 1000000000, // Minimum 10-digit number
//     max: 9999999999, // Maximum 10-digit number
//     required: true
//   },
//     hospital_clinic_name: {type:String, required: true},
//     specialization: {type:String, required: true},
//     years_of_experience: {type:Number, required: true, min: 0},
//     other_details: {type:String, required: true},
//     introduction: {type:String, required: true},
//     // profile_picture_url: String, // URL to the doctor's profile picture
// });
// const DoctorDetails = mongoose.model('DoctorDetails', DoctorDetailsSchema);

// const MotherDetailsSchema = new mongoose.Schema({
//     userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     contact_no: {
//     type: Number,
//     min: 1000000000, // Minimum 10-digit number
//     max: 9999999999, // Maximum 10-digit number
//     required: true
//   },
//     assigned_doctor: { type: mongoose.Schema.Types.ObjectId, ref: 'DoctorDetails' },
//     asha_worker_name: {type:String, required: true},
//     asha_worker_contact_no: {type:String, required: true},
//     date_of_pregnancy: {type:Date, required: true},
//     sonography_report_url: {type:String, required: true},
//     other_reports_url: {type:String, required: true},
//     disease_information: {
//         mother: { hereditary: {type:String, required: true}, non_hereditary: {type:String, required: true} },
//         father: { hereditary: {type:String, required: true}, non_hereditary: {type:String, required: true} },
//     },
// });
// const MotherDetails = mongoose.model('MotherDetails', MotherDetailsSchema);


// // --- Passport.js Google OAuth2 Strategy ---
// // passport.use(new GoogleStrategy({
// //     clientID: process.env.GOOGLE_CLIENT_ID,
// //     clientSecret: process.env.GOOGLE_CLIENT_SECRET,
// //     callbackURL: "/auth/google/callback"
// //   },
// //   async (accessToken, refreshToken, profile, done) => {
// //     try {
// //         let user = await User.findOne({ googleId: profile.id });
// //         if (user) {
// //             return done(null, user);
// //         }
        
// //         user = await User.findOne({ email: profile.emails[0].value });
// //         if (user) {
// //             user.googleId = profile.id;
// //             await user.save();
// //             return done(null, user);
// //         }

// //         // For new Google users, we need to know their status (Mother, Admin, Doctor)
// //         // This will be handled on the frontend after the initial google login redirect.
// //         const newUser = {
// //             googleId: profile.id,
// //             name: profile.displayName,
// //             email: profile.emails[0].value,
// //         };
// //         return done(null, newUser);

// //     } catch (err) {
// //         return done(err, false);
// //     }
// //   }
// // ));

// // --- File Upload (Multer) ---
// // Local Storage
// const storage = multer.diskStorage({
//     destination: function (req, file, cb) {
//         const dir = 'uploads/';
//         if (!fs.existsSync(dir)){
//             fs.mkdirSync(dir);
//         }
//         cb(null, dir);
//     },
//     filename: function (req, file, cb) {
//         cb(null, Date.now() + path.extname(file.originalname)); // Appending extension
//     }
// });

// const upload = multer({ 
//     storage: storage,
//     fileFilter: (req, file, cb) => {
//         // const allowedTypes = /jpeg|jpg|png|pdf/;
//         const allowedTypes = /jpeg|jpg/;
//         const mimetype = allowedTypes.test(file.mimetype);
//         const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
//         if (mimetype && extname) {
//             return cb(null, true);
//         }
//         cb("Error: File upload only supports the following filetypes - " + allowedTypes);
//     }
// });

// /*
// // --- Google Cloud Storage (Commented Out) ---
// const gcStorage = new Storage({
//     keyFilename: path.join(__dirname, 'your-gcloud-key.json'),
//     projectId: 'your-gcloud-project-id',
// });
// const bucket = gcStorage.bucket('your-gcloud-bucket-name');

// const gcUpload = multer({
//     storage: multer.memoryStorage(),
//     limits: {
//         fileSize: 5 * 1024 * 1024, // no larger than 5mb
//     },
// });

// const uploadToGCS = (req, res, next) => {
//     if (!req.file) {
//         return next();
//     }

//     const blob = bucket.file(Date.now() + path.extname(req.file.originalname));
//     const blobStream = blob.createWriteStream({
//         resumable: false,
//     });

//     blobStream.on('error', err => {
//         next(err);
//     });

//     blobStream.on('finish', () => {
//         req.file.cloudStoragePublicUrl = `https://storage.googleapis.com/${bucket.name}/${blob.name}`;
//         next();
//     });

//     blobStream.end(req.file.buffer);
// };
// */

// // --- Middleware to verify token (Moved before usage) ---
// // Middleware to verify token
// const auth = (req, res, next) => {
//     const token = req.header('x-auth-token');
//     if (!token) return res.status(401).json({ msg: 'No token, authorization denied' }); // <--- This is where "No token" comes from

//     try {
//         const decoded = jwt.verify(token, process.env.JWT_SECRET);
//         req.user = decoded.user;
//         next();
//     } catch (e) {
//         res.status(400).json({ msg: 'Token is not valid' }); // <--- This is where "Token is not valid" comes from
//     }
// };


// // --- API Routes ---

// // Auth Routes
// app.post('/api/register', async (req, res) => {
//     const { name, email, password, status } = req.body;
//     try {
//         let user = await User.findOne({ email });
//         if (user) return res.status(400).json({ msg: 'User already exists' });

//         user = new User({ name, email, password, status });
//         // In a real app, you'd hash the password
//         const salt = await bcrypt.genSalt(10);/////////
//         user.password = await bcrypt.hash(password, salt); ////////
//         await user.save();

//         const payload = { user: { id: user.id } };
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

//         // In a real app, you'd compare the hashed password
//         const isMatch = await bcrypt.compare(password, user.password);
//         // const isMatch = password === user.password; // Plain text comparison
//         if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

//         const payload = { user: { id: user.id } };
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

// app.post('/api/logout', auth, async (req, res) => {
//     try {
//         // Get the user ID from the authenticated token, not the request body
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
//     // On success, we need to handle what happens.
//     // If the user exists, we create a JWT and send them on their way.
//     // If it's a new user, we need them to select a status.
//     if (req.user.status) { // Existing user
//         const payload = { user: { id: req.user.id } };
//         jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '9M' }, async (err, token) => {
//             if (err) throw err;
//             req.user.jwtToken = token;
//             req.user.login_date_time = new Date();
//             await req.user.save();
//             // Redirect to a frontend route with the token
//             res.redirect(`http://0.0.0.0:3000/auth/google/success?token=${token}`);
//         });
//     } else { // New user
//         // Redirect to a frontend route for status selection
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


// // Details Routes
// // Around line 338
// // app.post('/api/details/admin', auth, async (req, res) => {
// //     const { contact_no, address } = req.body;
// //     try {
// //         const user = await User.findById(req.user.id);
// //         let details = await AdminDetails.findOne({ userId: req.user.id });
// //         if (details) {
// //             details.contact_no = contact_no;
// //             details.address = address;
// //         } else {
// //             details = new AdminDetails({
// //                 userId: req.user.id,
// //                 name: user.name,
// //                 email: user.email,
// //                 contact_no,
// //                 address
// //             });
// //         }
// //         await details.save();
// //         res.json(details);
// //     } catch (err) {
// //         console.error(err.message);
// //         res.status(500).send('Server Error');
// //     }
// // });
// app.post('/api/details/admin', auth, upload.none(), async (req, res) => {
//     const { contact_no, address } = req.body; // req.body will now be populated
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

// // app.post('/api/details/doctor', auth, async (req, res) => {
// //     const { contact_no, hospital_clinic_name, specialization, years_of_experience, other_details, introduction } = req.body;
// //     try {
// //         const user = await User.findById(req.user.id);
// //         let details = await DoctorDetails.findOne({ userId: req.user.id });
// //         if (details) {
// //             details.contact_no = contact_no;
// //             details.hospital_clinic_name = hospital_clinic_name;
// //             details.specialization = specialization;
// //             details.years_of_experience = years_of_experience;
// //             details.other_details = other_details;
// //             details.introduction = introduction;
// //         } else {
// //             details = new DoctorDetails({
// //                 userId: req.user.id,
// //                 name: user.name,
// //                 email: user.email,
// //                 contact_no, hospital_clinic_name, specialization, years_of_experience, other_details, introduction
// //             });
// //         }
// //         await details.save();
// //         res.json(details);
// //     } catch (err) {
// //         console.error(err.message);
// //         res.status(500).send('Server Error');
// //     }
// // });

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

// app.get('/api/doctors', auth, async (req, res) => {
//     try {
//         const doctors = await DoctorDetails.find().select('name_id');
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

//         const sonography_report_url = req.files['sonography_report'] ? `/uploads/${req.files['sonography_report'][0].filename}` : (details ? details.sonography_report_url : undefined);
//         const other_reports_url = req.files['other_reports'] ? `/uploads/${req.files['other_reports'][0].filename}` : (details ? details.other_reports_url : undefined);

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


// const PORT = process.env.PORT || 3000;
// app.listen(PORT, '0.0.0.0', () => console.log(`Server started on port ${PORT}`));
// // Export the app for testing purposes
// module.exports = app;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// server.js    

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

// --- Cloudinary Configuration ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});
// Middleware
app.use(cors());
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


// --- Passport.js Google OAuth2 Strategy (commented out in your code) ---
// If you enable this, ensure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are in .env
// passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID,
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET,
//     callbackURL: "/auth/google/callback"
//   },
//   async (accessToken, refreshToken, profile, done) => {
//     try {
//         let user = await User.findOne({ googleId: profile.id });
//         if (user) {
//             return done(null, user);
//         }
        
//         user = await User.findOne({ email: profile.emails[0].value });
//         if (user) {
//             user.googleId = profile.id;
//             await user.save();
//             return done(null, user);
//         }

//         const newUser = {
//             googleId: profile.id,
//             name: profile.displayName,
//             email: profile.emails[0].value,
//         };
//         return done(null, newUser);

//     } catch (err) {
//         return done(err, false);
//     }
//   }
// ));


// --- File Upload (Multer) ---
// Local Storage
// const storage = multer.diskStorage({
//     destination: function (req, file, cb) {
//         const dir = 'uploads/';
//         if (!fs.existsSync(dir)){
//             fs.mkdirSync(dir);
//         }
//         cb(null, dir);
//     },
//     filename: function (req, file, cb) {
//         cb(null, Date.now() + path.extname(file.originalname)); // Appending extension
//     }
// });

// --- UPDATED: File Upload (Multer with Cloudinary Storage for Images Only) ---
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'maternal_reports',
        // transformation: [{ fetch_format: 'jpg' }],
        public_id: (req, file) => `${file.fieldname}-${Date.now()}`,
    },
});

// const upload = multer({
//     storage: storage,
//     fileFilter: (req, file, cb) => {
//         // This filter only allows image file types.
//         const allowedTypes = /jpeg|jpg|png|gif|webp/;
//         const mimetype = allowedTypes.test(file.mimetype);
//         if (mimetype) {
//             return cb(null, true);
//         }
//         cb(new Error("Error: File upload only supports image formats."));
//     }
// });
////////////////////////////////////new///////////////////////////////////////////
// const upload = multer({
//     storage: storage,
//     fileFilter: (req, file, cb) => {
//         // Check both the mimetype and the file extension
//         const isImageMime = file.mimetype.startsWith('image');
//         const allowedExtensions = /.\.(jpg|jpeg|png|gif)$/i;
//         const isImageExt = allowedExtensions.test(path.extname(file.originalname));

//         if (isImageMime || isImageExt) {
//             cb(null, true);
//         } else {
//             cb(new Error("File upload only supports image formats."), false);
//         }
//     }
// });
///////////////////////////////////////////////////////////////////////////
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        // Allow common image MIME types and PDF MIME type
        const allowedMimeTypes = /jpeg|jpg|png|gif|webp|pdf/;
        const mimetype = allowedMimeTypes.test(file.mimetype);

        // Allow common image extensions and PDF extension
        const allowedExtensions = /.\.(jpg|jpeg|png|gif|pdf)$/i;
        const extname = allowedExtensions.test(path.extname(file.originalname));

        if (mimetype && extname) {
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


// app.post('/api/details/mother', auth, upload.fields([{ name: 'sonography_report', maxCount: 1 }, { name: 'other_reports', maxCount: 1 }]), async (req, res) => {
//     const { contact_no, assigned_doctor, asha_worker_name, asha_worker_contact_no, date_of_pregnancy, disease_information } = req.body;
//     try {
//         const user = await User.findById(req.user.id);
//         let details = await MotherDetails.findOne({ userId: req.user.id });

//         const sonography_report_url = req.files['sonography_report'] ? `/uploads/${req.files['sonography_report'][0].filename}` : (details ? details.sonography_report_url : undefined);
//         const other_reports_url = req.files['other_reports'] ? `/uploads/${req.files['other_reports'][0].filename}` : (details ? details.other_reports_url : undefined);

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


const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server started on port ${PORT}`));
// module.exports = app;