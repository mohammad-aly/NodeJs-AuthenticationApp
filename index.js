import express, { urlencoded } from 'express';
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();

mongoose.connect("mongodb://127.0.0.1:27017", {
    dbName: 'backend',
}).then(()=> console.log("Connected to database"))
.catch((err)=> console.log(err))

const UserSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
})

const User = mongoose.model('User',UserSchema)


//using middleware
app.use(express.static(path.join(path.resolve(),"public")));
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser());


app.set("view engine", "ejs");

const isAuthenticated = async (req, res, next)=>{

    const {token} = req.cookies;

    if(token){
        const decode = jwt.verify(token,"qwerty");
        req.user = await User.findById(decode._id);

        next()
    }
    else{
        res.redirect("login")
    }
}

app.get("/login", (req, res) => {
    res.render("login");
})

app.get("/", isAuthenticated, (req, res) => {
    res.render("logout",{name:req.user.name});
})


app.post("/login", async (req, res) => {
    const {email, password} = req.body;

    let user = await User.findOne({email});

    if(!user) return res.redirect("/register");

    const isMatch = await bcrypt.compare(password, user.password);

    if(!isMatch) return res.render("login",{email, message : "Incorrect password"});

    const token = jwt.sign({_id: user._id},"qwerty")

    res.cookie("token", token,{
        httpOnly: true, expires: new Date(Date.now()+60*1000)
    })
    res.redirect("/");

})

app.get("/register", (req, res) => {
    res.render("register")
})

app.post('/register', async (req, res) => {

    const {name,email,password} = req.body;

    let user = await User.findOne({email})
    if(user){
        return res.render("login")
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user = await User.create({
        name,
        email,
        password: hashedPassword,
    })

    const token = jwt.sign({_id: user._id},"qwerty")

    res.cookie("token", token,{
        httpOnly: true, expires: new Date(Date.now()+60*1000)
    })
    res.redirect("/");
})


app.get('/logout', (req, res) => {
    res.cookie("token", null,{
        httpOnly: true, expires: new Date(Date.now())
    })
    res.redirect("/");
})


app.listen(5000, () => {
    console.log("connected!!")
})