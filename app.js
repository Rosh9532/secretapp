require('dotenv').config()
const express=require("express");
const bodyParser=require("body-parser");
const https=require("https");
const mongoose=require('mongoose');
//const encrypt = require('mongoose-encryption');
//const md5 = require('md5');
const bcrypt = require('bcrypt');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-find-or-create')

//const saltRounds = 1;
//const User = require('./models/user');

//const request=require("request");
const app=express();
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));



app.use(session({
	secret:"Our little secret.",
	resave:false,
	saveUninitialized:false
	
}
));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(`${process.env.MONGO_URI}`, {
    useUnifiedTopology: true,
    useNewUrlParser: true,
    useCreateIndex: true
})
    .then(() => console.log("Connected to Database"))
    .catch(err => console.error("An error has occured", err));

mongoose.set('useCreateIndex', true);
const userSchema =new mongoose.Schema({
	email: String,
    password: String,
	googleId:String,
	secret:String
	
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//userSchema.plugin(encrypt,{secret:secret,encryptedFields: ['password']});
const User=new mongoose.model("User",userSchema);

// use static authenticate method of model in LocalStrategy

passport.use(User.createStrategy());

//passport.serializeUser(User.serializeUser());
//passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
	userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
	  console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/",function(request,response){
	response.render("home")
});



app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));
  
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });  


app.get("/login",function(request,response){
	response.render("login");
});

app.get("/register",function(request,response){
	response.render("register");
	});
	
app.get("/secrets",function(request,response){
	if(request.isAuthenticated()){
		response.render("secrets");
	}else{
		response.redirect("/login");
	}
});

app.get("/secrets",function(request,response){
	User.find({"secret":{$ne:null}},function(err,foundUsers){
		if(err){
			console.log(err);
		}else{
			if(foundUsers){
				response.render("secrets",{userswithSecrets:foundUsers})
			}
		}
	});
	
	});

app.get("/submit",function(request,response){
	if(request.isAuthenticated()){
		response.render("submit");
	}else{
		response.redirect("/login");
	}
	});
	
app.post("/submit",function(request,response){
	const submitsecret=request.body.secret
	console.log(request.user.id);
	User.findById(request.user.id,function(err,foundUser){
		if(err){
			console.log(err);
		}else{
			if(foundUser){
				foundUser.secret=submitsecret;
				foundUser.save(function(){
					response.redirect("/secrets");
				});
			}
			
		}
	});
});
	
	
/*app.post("/register",function(request,response){
	User.register({username:request.body.username},request.body.password,function(err,user){
		if(err){
			console.log("noo");
			response.redirect("/register");
		}else{
			passport.authenticate("local")(request,response,function(){
			  response.redirect("/secrets")	
			});
		}
	});
});*/
app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});


app.post("/login",function(request,response){
	const user=new User({
		username:request.body.username,
		password:request.body.password
	}
	);
	request.login(user,function(err){
		if(err){
		
			console.log(err);
			
		}else{
			passport.authenticate("local")(request, response, function(){
				
             response.redirect("/secrets");
      });
		}
	})
});	
	
app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});	

/*app.post("/register",function(request,response){
	
	bcrypt.hash(request.body.password, saltRounds, function(err, hash) {
    const newUser=new User({
		email:request.body.username,
		//password:md5(request.body.password)
		password:hash
	});
newUser.save(function(err){
	if(err){
		console.log(err);
	}else{
		response.render("secrets");
	}
});
});
	
	
});

app.post("/login",function(request,response){
	const username=request.body.username;
	const password=md5(request.body.password);
	
	User.findOne({email:username},function(err,foundUser){
		if(err){
			console.log(err);
		}else{
			if(foundUser){
				/*if(foundUser.password===password){
					response.render("register");
				}*/
				//bcrypt.compare(password,foundUser.password, function(err, result) {
    // result == true
	              /* if(result == true){
					   response.render("register");
				   }
                });
			}
		}
	});*/
	
	
//});
app.listen(
    process.env.PORT || 3000, 
    console.log("Server started")
);

