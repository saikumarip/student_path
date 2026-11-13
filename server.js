
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required.");
}

const db = new sqlite3.Database(
  path.join(__dirname, "studentpath.db")
);

const run = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });

const get = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });

app.use(helmet());
app.use(express.json({limit:"10kb"}));
app.use(express.static(__dirname));

app.use(session({
  store: new SQLiteStore({
    db: "sessions.sqlite",
    dir: __dirname
  }),
  name: "studentpath.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 86400000
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10
});

const levels = [
  "10th Class",
  "Intermediate",
  "Degree",
  "Other"
];

app.get("/", (req,res) => {
  res.sendFile(path.join(__dirname,"index.html"));
});

async function initializeDatabase() {
  await run(`
    CREATE TABLE IF NOT EXISTS students (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      education_level TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

app.post("/api/register",authLimiter,async(req,res)=>{
  try {
    const {name,email,password,level}=req.body;

    if(typeof name!=="string" ||
       typeof email!=="string" ||
       typeof password!=="string" ||
       typeof level!=="string" ||
       !name.trim() || name.length>100 ||
       password.length<8 || password.length>128 ||
       !levels.includes(level)) {
      return res.status(400).json({
        error:"Please enter valid details. Password must have at least 8 characters."
      });
    }

    const cleanEmail=email.trim().toLowerCase();

    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)){
      return res.status(400).json({error:"Enter a valid email."});
    }

    const existing=await get(
      "SELECT id FROM students WHERE email=?",
      [cleanEmail]
    );

    if(existing){
      return res.status(409).json({
        error:"This email is already registered."
      });
    }

    const hash=await bcrypt.hash(password,12);

    await run(
      `INSERT INTO students
      (name,email,password_hash,education_level)
      VALUES(?,?,?,?)`,
      [name.trim(),cleanEmail,hash,level]
    );

    res.status(201).json({
      message:"Registration successful. Please log in."
    });

  } catch(err) {
    console.error(err);
    res.status(500).json({error:"Registration failed."});
  }
});

app.post("/api/login",authLimiter,async(req,res)=>{
  try {
    const {email,password}=req.body;

    if(typeof email!=="string" ||
       typeof password!=="string") {
      return res.status(400).json({error:"Enter email and password."});
    }

    const student=await get(
      "SELECT * FROM students WHERE email=?",
      [email.trim().toLowerCase()]
    );

    if(!student || !(await bcrypt.compare(
      password,student.password_hash
    ))) {
      return res.status(401).json({
        error:"Incorrect email or password."
      });
    }

    req.session.regenerate(err=>{
      if(err){
        return res.status(500).json({error:"Login failed."});
      }

      req.session.studentId=student.id;

      res.json({
        message:"Login successful.",
        student:{
          id:student.id,
          name:student.name,
          email:student.email,
          level:student.education_level
        }
      });
    });

  } catch(err) {
    console.error(err);
    res.status(500).json({error:"Login failed."});
  }
});

app.get("/api/me",async(req,res)=>{
  if(!req.session.studentId){
    return res.status(401).json({error:"Please log in."});
  }

  try{
    const student=await get(
      `SELECT id,name,email,education_level
       FROM students WHERE id=?`,
      [req.session.studentId]
    );

    if(!student){
      return res.status(401).json({error:"Student not found."});
    }

    res.json({student});
  }catch(err){
    res.status(500).json({error:"Could not load profile."});
  }
});

app.post("/api/logout",(req,res)=>{
  req.session.destroy(err=>{
    if(err){
      return res.status(500).json({error:"Logout failed."});
    }
    res.clearCookie("studentpath.sid");
    res.json({message:"Logged out successfully."});
  });
});

app.get("/api/courses",(req,res)=>{
  res.json([
    {name:"Intermediate MPC",category:"After 10th"},
    {name:"Intermediate BiPC",category:"After 10th"},
    {name:"Diploma Courses",category:"After 10th"},
    {name:"B.Tech & Engineering",category:"After Inter"},
    {name:"Medical & Life Sciences",category:"After Inter"},
    {name:"Degree Courses",category:"After Inter"}
  ]);
});

app.get("/api/scholarships",(req,res)=>{
  res.json([
    {name:"Merit Scholarships",type:"Academic achievement"},
    {name:"Government Schemes",type:"Government support"},
    {name:"Financial Assistance",type:"Education fee support"}
  ]);
});

async function start(){
  await initializeDatabase();

  app.listen(PORT,"0.0.0.0",()=>{
    console.log("StudentPath server running on port "+PORT);
  });
}

start().catch(err=>{
  console.error("Server startup failed:",err);
  process.exit(1);
});
