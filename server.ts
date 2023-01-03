import express, { Express, NextFunction, Request, Response } from 'express';
import cors from 'cors'
import jsonwebtoken from 'jsonwebtoken';
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'
import { GridFSBucket, MongoClient} from 'mongodb';
import multer from 'multer';
import mongoose from 'mongoose';
import { GridFsStorage } from 'multer-gridfs-storage';


dotenv.config()

const uri = 'mongodb+srv://pngu:AB0dNaJUXo9bdS27@tedavi100.2dpkus9.mongodb.net/?retryWrites=true&w=majority'
const client = new MongoClient(uri)
const dbStorage = client.connect().then(cl => cl.db('Timemanagement'))

const storage = new GridFsStorage({client, db:dbStorage,  file: (req, file) => {
    if (file.mimetype === 'image/jpeg') {
      return {
       bucketName:'profilepics'
      };
    } else {
      return null;
    }
  }})

const upload = multer({storage})

const PORT = process.env.PORT || 3000;
const app:Express = express()
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({extended:true}))

interface User  {
    name:string,
    password:string,
    imgfile:string
}

interface Log {
    name:string,
    timestamp: number,
    isLogged: boolean
}

export interface CustomRequest extends Request {
    token?: string;
    data?: any;
  }


const SECRET_KEY = String(process.env.SECRET_KEY)


// LOGIN
app.post("/login", checkPassword, verifyToken ,(req:CustomRequest, res:Response)=> {
    res.send({msg:req.token})
})

// PROTECTED ROUTE
app.get("/home", checkToken ,verifyToken , (req:CustomRequest,res:Response)=> {
    const user:string = req.data.name
    res.send({msg:user})
})


//Check User
async function checkPassword(req:CustomRequest,res:Response,next:NextFunction) {
    const name:string = req.body.name 
    const password:string = req.body.password
    if (!name || !password) return res.status(401).send({msg:"Please check username or password!"})
    //check user
   const foundUser = (await getUsers()).filter((user)=> user.name === name)
    if (foundUser.length === 0 ) return res.status(401).send({msg:"user not found!"})
    // check password bcyrpt
    const passwordEncrypted  = await bcrypt.compare(password , foundUser[0].password)
    if (!passwordEncrypted) return res.status(401).send({msg:"password not correct!"})
    // sign token
    const jwt =  jsonwebtoken.sign({name:foundUser[0].name}, SECRET_KEY, {expiresIn:'1h'})
    req.token = jwt
    next()
}

// Load DB Users
async function getUsers() {
    const database = client.db('Timemanagement')
     const collection = database.collection<User>("user")
     const usercollection = collection.find({})
     const data = await usercollection.toArray() 
     return data
}

async function getLogs() {
    const database = client.db("Timemanagement")
    const collection = database.collection<Log>("log")
    const logcollection = collection.find({})
    const data = await logcollection.toArray()
    return data
}


// check and verify TOKEN
function checkToken(req:CustomRequest,res:Response,next:NextFunction) {
    // req.headers["authorization"] = "BEARER "+token
    const header = String(req.headers["authorization"])
    if (typeof header !== undefined) {
        const bearer = header.split(' ');
        const token = bearer[1];
        req.token = token    
    }
    else {
        res.status(403).send({msg:"no token included!"})
    }
    next()
}


function verifyToken(req:CustomRequest,res:Response,next:NextFunction) {
    const token = String(req.token)
     try {
        req.data = jsonwebtoken.verify(token, SECRET_KEY)
     } 
     catch (err) {
        return res.status(403).send({msg: err})
     }
    next()
}


//REGISTER USER
app.post("/registration",registerUser,(req:CustomRequest,res:Response)=> {  
    res.send({msg:"Token: " + req.token})
   })


async function registerUser(req:CustomRequest,res:Response,next:NextFunction) {
        let filterUser = (await getUsers()).filter((user)=> user.name === req.body.name.toString())
        if (filterUser.length > 0) return res.status(401).send({msg:"User already exists!"})
        if (String(req.body.password).length === 0 || !req.body.password) return res.status(401).send({msg:"Please enter a password!"})
        if (req.body.password !== req.body.passwordrepeat) return res.status(401).send({msg:"passwords do not match!"})
        const hashpassword = await bcrypt.hash(req.body.password,10)
        let user:User = {
            name:req.body.name.toString(),
            password:hashpassword,
            imgfile:'',
            }   
        const jwt =  jsonwebtoken.sign({name:user.name}, SECRET_KEY, {expiresIn:'1h'})
        // Save User + Key in Database
            saveUser(user)
        req.token  = jwt
        next()
    }  


function saveUser(user:User){
     const database = client.db('Timemanagement')
     const collection = database.collection<User>("user")
     collection.insertOne(user)
}

function saveLog(log:Log) {
    const database = client.db("Timemanagement")
    const collection = database.collection<Log>("log")
    collection.insertOne(log)
}


// GET ALL USERS
app.get("/users",async(req:Request,res:Response)=> {
    res.send({msg:(await getUsers())})
})


// USER LOGS GET AND POST
app.route("/logs")
.get( checkToken,verifyToken,async (req:CustomRequest,res:Response)=> {
    // filter userlogs by month
  //  const month:number = req.body.month
  //  if (!month) return res.status(401).send({msg:"no month given"})
    const filteredLogs = (await getLogs()).filter((log)=>
     log.name === String(req.data.name))
   res.send({msg:filteredLogs})
})
.post(checkToken,verifyToken, async(req:CustomRequest,res:Response)=> {
    let user =  (await getUsers()).filter((user)=> user.name === String(req.data.name))
    console.log(user)
    if (user.length === 0) return res.status(401).send({msg:"User not found!"})
    if ( isNaN(new Date(req.body.timestamp).getTime()) ===  true) return res.status(401).send({msg:"Date not correct!"})
    
    let log:Log
    let userLogs:Log[] = (await getLogs()).filter((log)=>log.name === String(req.data.name))
    
    if (userLogs.length === 0) {
        log = {
            name: String(req.data.name),
            timestamp: new Date(req.body.timestamp).getTime(),
            isLogged: true
        }
    }

    else {
        // Check lastTimestamp
        if (new Date(req.body.timestamp).getTime() <= userLogs[userLogs.length-1].timestamp) 
        return res.status(401).send({msg:"Datetime smaller than last Time!"})

        log = {
            name:String(req.data.name),
            timestamp: new Date(req.body.timestamp).getTime(),
            isLogged:  userLogs[userLogs.length-1].isLogged ? false : true
        }
    }

    // Save Log
    saveLog(log)
    res.send({msg:log})
})


//total hours
app.post("/total",checkToken,verifyToken,calculate ,(req:CustomRequest,res:Response)=> {
   console.log("total success!")
})


//middleware calculate
async function calculate(req:CustomRequest, res:Response, next:NextFunction) {
    const name:string = String(req.data.name) // req.data from header authorization
    const month:number = Number(req.body.month)
   // const year:number = Number(req.body.year) 

    const individalLogs:Log[] = (await getLogs()).filter((log)=> log.name === name
    && new Date(log.timestamp).getMonth() === month
    )
    if (individalLogs.length === 0) return res.status(401).send({msg:"user not found!"})
    const userlogs = individalLogs.map((item)=> item.timestamp)

    let hoursList:number[] = []
    let previousNum:number = 0

    userlogs.forEach((item,index)=> {
        if (index % 2 === 0) previousNum = item
        if(index % 2 !== 0) {
            hoursList.push(item-previousNum)
        }
    })
    const totalHours =  hoursList.reduce((a,b)=> a+b, 0) /(1000*60*60)
    res.send({msg:totalHours})
    next()
}


let conn = mongoose.createConnection(uri)
let bucket:GridFSBucket

conn.once("open", async ()=> {
    bucket = new GridFSBucket(client.db('Timemanagement'), {bucketName:'profilepics'})
})


app.post('/uploadimage',checkToken, verifyToken, upload.single('photo'), (req:CustomRequest,res:Response)=> {
    console.log(req.data.name)
    const database = client.db('Timemanagement')
    const collection = database.collection<User>("user")
    collection.updateOne({"name":req.data.name}, {$set: {"imgfile":req.file?.filename}})
    res.send({msg:req.file})
})



app.get('/images/:name', async (req:Request,res:Response)=> {
    const users = (await getUsers()).filter((user)=> user.name === String(req.params.name))
    const imgName = users[0].imgfile
    console.log(users)

    let stream;
    try {
        stream =  bucket.openDownloadStreamByName(imgName) 
         stream.pipe(res)
    }
    
    catch(err) {
        console.log("fehler: "+ err)
       return res.status(401).send({msg:err})
    }
})


app.listen(PORT, ()=> {
    console.log("Server running on Port " + PORT)
})
