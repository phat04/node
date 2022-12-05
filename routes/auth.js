const router = require("express").Router();
const User = require("../models/User");
const Token = require("../models/Token");
const CryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const passportJWT = require("passport-jwt");
const nodemailer = require("nodemailer");
const { tokenTypes } = require("../config/Tokens");

var transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: "ghjnnii@gmail.com",
    pass: "havchprfkkcvlecm",
  },
});

//var refreshTokens = {};

let JwtStrategy = passportJWT.Strategy,
  ExtractJwt = passportJWT.ExtractJwt;

let JwtOptions = {};
JwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
JwtOptions.secretOrKey = "wow";

passport.use(
  new JwtStrategy(JwtOptions, async (payload, done) => {
    if (!payload.sub) {
      return done(null, false);
    }
    const user = await User.findById(payload.sub);
    if (user) {
      return done(null, user);
    }
    return done(null, false);
  })
);

router.use(passport.initialize());

//Register
router.post("/register", async (req, res) => {
  const newUser = new User({
    username: req.body.username,
    email: req.body.email,
    //password: req.body.password,
    password: CryptoJS.AES.encrypt(
      req.body.password,
      process.env.PASS_SEC
    ).toString(),
  });

  try {
    await newUser.save();
  } catch (err) {
    return res.status(500).send(err);
  }

  var tokenVerifyEmail = new Token({
    _userId: newUser._id,
    token: jwt.sign(
      { sub: newUser._id },
      process.env.VERIFY_EMAIL_TOKEN_SECRET,
      {
        expiresIn: "300s",
      }
    ),
    type: tokenTypes.VERIFY_EMAIL,
  });
  try {
    await tokenVerifyEmail.save();
  } catch (err) {
    return res.status(500).send(err);
  }

  var mailOptions = {
    from: "ghjnnii@gmail.com",
    to: newUser.email,
    subject: "Account Verification Link",
    text:
      "Hello " +
      req.body.username +
      ",\n\n" +
      "Please verify your account by clicking the link: \nhttp://" +
      req.headers.host +
      "/auth/confirmation/" +
      tokenVerifyEmail.token,
  };
  try {
    await transporter.sendMail(mailOptions);
    return res
      .status(200)
      .send(
        "A verification email has been sent to " +
          newUser.email +
          ". It will be expire after one day. If you not get verification Email click on resend token."
      );
  } catch (err) {
    return res.status(500).send({
      msg: "Technical Issue!, Please click on resend for verify your Email.",
    });
  }
});

const confirmEmail = async (req, res, next) => {
  try {
    const tokenVerifyEmail = await Token.findOne({ token: req.params.token });

    const user = await User.findOne({ _id: tokenVerifyEmail._userId });
    if (user.isConfirmEmail) {
      return res
        .status(200)
        .send("User has been already verified. Please Login");
    } else {
      // change isConfirmEmailto true
      user.isConfirmEmail = true;
      await user.save();

      return res
        .status(200)
        .send("Your account has been successfully verified");
    }
  } catch (err) {
    console.log(err);
  }
};

router.get("/confirmation/:token", confirmEmail);

//LOGIN
router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    !user && res.status(401).json("Wrong credentials");
    const hashedPassword = CryptoJS.AES.decrypt(
      user.password,
      process.env.PASS_SEC
    );
    const originalPassword = hashedPassword.toString(CryptoJS.enc.Utf8);
    originalPassword !== req.body.password &&
      res.status(401).json("Wrong credentials");
    //const payload = { sub: user._id };

    const accessToken = new Token({
      _userId: newUser._id,
      token: jwt.sign({ sub: newUser._id }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "300s",
      }),
      type: tokenTypes.ACCESS,
    });

    // const accessToken = jwt.sign(payload, JwtOptions.secretOrKey, {
    //   expiresIn: "300s",
    // });

    const refreshToken = new Token({
      _userId: newUser._id,
      token: jwt.sign({ sub: newUser._id }, process.env.RESFRESH_TOKEN_SECRET, {
        expiresIn: "300s",
      }),
      type: tokenTypes.REFRESH,
    });

    // const refreshToken = jwt.sign(payload, process.env.RESFRESH_TOKEN_SECRET, {
    //   expiresIn: "3d",
    // });
    const response = { user, accessToken, refreshToken };
    //refreshTokens[refreshToken] = response;
    res.json(response);
    //const { password, ...others } = user._doc;
    //res.status(200).json({ ...others, accessToken });
    //res.status(200).json(user);
  } catch (err) {
    console.log(err);
    res.status(500).json(err);
  }
});

router.get(
  "/protected",
  passport.authenticate("jwt", { session: false }),
  function (req, res) {
    res.json("Success! You can now see this without a token.");
  }
);

router.get(
  "/protected1",
  async (req, res, next) => {
    try {
      return passport.authenticate("jwt", { session: false })(req, res, next);
    } catch (err) {
      console.log(err);
    }
  },
  (req, res) => {
    res.json("Success! You can now see this without a token.");
  }
);

router.post("/getToken", async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken && refreshToken in refreshTokens) {
    const user = await User.findOne({ username: req.body.username });
    const payload = { sub: user._id };
    const accessToken = jwt.sign(payload, JwtOptions.secretOrKey, {
      expiresIn: "300s",
    });
    refreshTokens[refreshToken].accessToken = accessToken;
    res.json([refreshTokens[refreshToken]]);
    //res.json([refreshTokens]);
  } else {
    res.json("Invalid");
  }
});

router.get("/forgotPassword", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    var mailOptions = {
      from: "ghjnnii@gmailcom",
      to: user.email,
      subject: "Forgot Password",
      text:
        "Hello " +
        user.username +
        "\n\n" +
        "Please provide password by click link:\nhttp://" +
        req.headers.host +
        "/auth/regetPassword/" +
        user._id,
    };
    await transporter.sendMail(mailOptions);
    res.json("A verification email has been sent to " + user.email);
  } catch (err) {
    console.log(err);
    return;
  }
});

router.get("/regetPassword/:id", async (req, res) => {
  try {
    const token = await Token.findOne({ token: req.params.token });
    const user = await User.findOne({ _id: req.params.id });

    res.send("password is:" + user.password);
  } catch (err) {
    console.log(err);
    return res.send("Unauthoriza");
  }
});

router.get("/resetPassword", async (req, res) => {
  try {
    const token = await Token.findOne({ token: req.body.accessToken });
    const user = await User.findOne({ username: req.body.username });
    console.log(token);
    var mailOptions = {
      from: "ghjnnii@gmail.com",
      to: user.email,
      subject: "I want to reset Password",
      text:
        "Hi " +
        user.username +
        ",\n\nPleas reset password by click link:\nhttp://" +
        req.headers.host +
        "/auth/setPassword/" +
        token.token,
    };
    await transporter.sendMail(mailOptions);
    res.json(
      "A verification email has been sent to " +
        user.email +
        " to reset password"
    );
  } catch (err) {
    console.log(err);
    return;
  }
});

router.post("/setPassword/:token", async (req, res) => {
  try {
    const user = await User.findOneAndUpdate(
      { _id: req.params.token },
      { $set: req.body },
      { new: true }
    );
    return res.json(user.password);
  } catch (err) {
    console.log(err);
    return;
  }
});

module.exports = router;
//process.env.RESFRESH_TOKEN_SECRET
