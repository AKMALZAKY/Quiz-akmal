const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({limit:'1mb'}));
app.use(express.static(path.join(__dirname,'public')));

const PORT = process.env.PORT || 3000;
const AUTH_SECRET = process.env.AUTH_SECRET || 'change-this-secret-in-production';
const DB_FILE = path.join(__dirname, 'data.json');

function loadDB(){
  try { return JSON.parse(fs.readFileSync(DB_FILE,'utf8')); }
  catch { return {teachers:[], quizzes:[]}; }
}
function saveDB(db){
  const tmp = DB_FILE+'.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db,null,2));
  fs.renameSync(tmp, DB_FILE);
}
let db = loadDB();

function id(){ return crypto.randomUUID(); }
function code(){
  const chars='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s='';
  do{s=Array.from({length:6},()=>chars[Math.floor(Math.random()*chars.length)]).join('')}
  while(db.quizzes.some(q=>q.code===s));
  return s;
}
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){
  const hash=crypto.scryptSync(password,salt,64).toString('hex');
  return {salt,hash};
}
function verifyPassword(password,record){
  const {hash}=hashPassword(password,record.salt);
  return crypto.timingSafeEqual(Buffer.from(hash,'hex'),Buffer.from(record.hash,'hex'));
}
function makeToken(teacherId){
  const payload=Buffer.from(JSON.stringify({sub:teacherId,exp:Date.now()+1000*60*60*24*14})).toString('base64url');
  const sig=crypto.createHmac('sha256',AUTH_SECRET).update(payload).digest('base64url');
  return payload+'.'+sig;
}
function auth(req,res,next){
  const t=(req.headers.authorization||'').replace(/^Bearer\s+/,'');
  if(!t)return res.status(401).json({error:'Silakan masuk sebagai pembuat.'});
  const [payload,sig]=t.split('.');
  try{
    const good=crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(crypto.createHmac('sha256',AUTH_SECRET).update(payload).digest('base64url')));
    if(!good)throw 0;
    const p=JSON.parse(Buffer.from(payload,'base64url').toString());
    if(p.exp<Date.now())throw 0;
    const teacher=db.teachers.find(x=>x.id===p.sub); if(!teacher)throw 0;
    req.teacher=teacher; next();
  }catch{res.status(401).json({error:'Sesi tidak valid. Silakan masuk lagi.'})}
}
function publicQuiz(q){
  return {id:q.id,code:q.code,title:q.title,subject:q.subject,description:q.description,questions:q.questions.map(x=>({text:x.text,points:x.points,options:x.options}))};
}

app.post('/api/register',(req,res)=>{
  const name=String(req.body.name||'').trim(),username=String(req.body.username||'').trim().toLowerCase(),password=String(req.body.password||'');
  if(name.length<2||username.length<3||password.length<6)return res.status(400).json({error:'Nama minimal 2 karakter, username 3 karakter, password minimal 6 karakter.'});
  if(!/^[a-z0-9._-]+$/.test(username))return res.status(400).json({error:'Username hanya boleh huruf kecil, angka, titik, garis bawah, atau strip.'});
  if(db.teachers.some(t=>t.username===username))return res.status(409).json({error:'Username sudah dipakai.'});
  const pw=hashPassword(password);
  const teacher={id:id(),name,username,passwordHash:pw.hash,passwordSalt:pw.salt,createdAt:new Date().toISOString()};
  db.teachers.push(teacher);saveDB(db);
  res.json({token:makeToken(teacher.id),teacher:{id:teacher.id,name:teacher.name,username:teacher.username}});
});
app.post('/api/login',(req,res)=>{
  const username=String(req.body.username||'').trim().toLowerCase(),password=String(req.body.password||'');
  const teacher=db.teachers.find(t=>t.username===username);
  if(!teacher||!verifyPassword(password,{hash:teacher.passwordHash,salt:teacher.passwordSalt}))return res.status(401).json({error:'Username atau password salah.'});
  res.json({token:makeToken(teacher.id),teacher:{id:teacher.id,name:teacher.name,username:teacher.username}});
});
app.get('/api/teacher/me',auth,(req,res)=>res.json({teacher:{id:req.teacher.id,name:req.teacher.name,username:req.teacher.username}}));
app.get('/api/teacher/dashboard',auth,(req,res)=>{
  const quizzes=db.quizzes.filter(q=>q.teacherId===req.teacher.id);
  const qs=quizzes.map(q=>({...publicQuiz(q),questions:q.questions.map(x=>({text:x.text,points:x.points,options:x.options})),submissionCount:q.submissions.length}));
  res.json({teacher:{id:req.teacher.id,name:req.teacher.name,username:req.teacher.username},quizzes:qs,stats:{quizzes:qs.length,submissions:qs.reduce((a,q)=>a+q.submissionCount,0)}});
});
app.post('/api/quizzes',auth,(req,res)=>{
  const {title,subject,description,questions}=req.body;
  if(!title||!subject||!Array.isArray(questions)||!questions.length)return res.status(400).json({error:'Judul, bidang pelajaran, dan soal wajib diisi.'});
  if(questions.length>100)return res.status(400).json({error:'Maksimal 100 soal per kuis.'});
  for(const q of questions){
    if(!q.text||!Array.isArray(q.options)||q.options.length!==5||q.options.some(x=>!String(x).trim())||!Number.isInteger(+q.points)||+q.points<1||+q.correct<0||+q.correct>4)
      return res.status(400).json({error:'Ada soal yang belum lengkap.'});
  }
  const quiz={id:id(),teacherId:req.teacher.id,code:code(),title:String(title).trim(),subject:String(subject).trim(),description:String(description||'').trim(),questions:questions.map(q=>({text:String(q.text).trim(),points:+q.points,options:q.options.map(x=>String(x).trim()),correct:+q.correct})),submissions:[],createdAt:new Date().toISOString()};
  db.quizzes.push(quiz);saveDB(db);
  res.json({quiz:publicQuiz(quiz)});
});
app.get('/api/quizzes/code/:code',(req,res)=>{
  const q=db.quizzes.find(x=>x.code===String(req.params.code).toUpperCase());
  if(!q)return res.status(404).json({error:'Kode kelas tidak ditemukan.'});
  res.json({quiz:publicQuiz(q)});
});
app.post('/api/quizzes/:code/submit',(req,res)=>{
  const q=db.quizzes.find(x=>x.code===String(req.params.code).toUpperCase());
  if(!q)return res.status(404).json({error:'Kuis tidak ditemukan.'});
  const name=String(req.body.name||'').trim(),answers=req.body.answers;
  if(name.length<1||name.length>60||!Array.isArray(answers)||answers.length!==q.questions.length)return res.status(400).json({error:'Data jawaban tidak valid.'});
  let score=0,correctCount=0;
  q.questions.forEach((x,i)=>{if(+answers[i]===x.correct){score+=x.points;correctCount++}});
  const totalPoints=q.questions.reduce((a,x)=>a+x.points,0);
  const sub={id:id(),name,score,totalPoints,correctCount,totalQuestions:q.questions.length,submittedAt:new Date().toISOString()};
  q.submissions.push(sub);saveDB(db);
  res.json(sub);
});
app.get('/api/quizzes/:id/submissions',auth,(req,res)=>{
  const q=db.quizzes.find(x=>x.id===req.params.id && x.teacherId===req.teacher.id);
  if(!q)return res.status(404).json({error:'Kuis tidak ditemukan.'});
  const totalPoints=q.questions.reduce((a,x)=>a+x.points,0);
  res.json({quiz:publicQuiz(q),submissions:q.submissions,totalPoints});
});
app.delete('/api/quizzes/:id',auth,(req,res)=>{
  const before=db.quizzes.length;
  db.quizzes=db.quizzes.filter(q=>!(q.id===req.params.id&&q.teacherId===req.teacher.id));
  if(db.quizzes.length===before)return res.status(404).json({error:'Kuis tidak ditemukan.'});
  saveDB(db);res.json({ok:true});
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

app.listen(PORT,()=>console.log(`QuizCraft berjalan di http://localhost:${PORT}`));
