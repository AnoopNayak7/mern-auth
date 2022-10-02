const Admin = require("../models/userModal");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const userCtrl = {
  register: async (req, res) => {
    try {
      const { name, email, password } = req.body;
      if (!name || !email || !password)
        return res.status(400).json({ msg: "Please fill in all fields." });

      if (!validateEmail(email))
        return res.status(400).json({ msg: "Invalid emails." });

      const admin = await Admin.findOne({ email });
      if (admin)
        return res.status(400).json({ msg: "This email already exists" });

      if (password.length < 6)
        return res
          .status(400)
          .json({ msg: "Password must be at least 6 characters" });

      const passwordHash = await bcrypt.hash(password, 12);

      const newAdmin = new Admin({
        name,
        email,
        password: passwordHash,
      });

      await newAdmin.save();

      res.json({ msg: "Register successfull" });
    } catch (err) {
      return res.status(500).json({ msg: err.message });
    }
  },

  login: async (req, res) => {
    try {
      const { email, password } = req.body;
      const admin = await Admin.findOne({ email });

      if (!admin)
        return res.status(400).json({ msg: "This email doesnt exists" });

      const isMatch = await bcrypt.compare(password, admin.password);
      if (!isMatch)
        return res.status(400).json({ msg: "Password is incorrect" });

      const refresh_token = createRefreshToken({ id: admin._id });
      res.cookie("refreshtoken", refresh_token, {
        httpOnly: true,
        path: "/auth/v1/refresh_token",
        maxAge: 7 * 24 * 60 * 60 * 1000, //7 days
      });
      console.log(refresh_token);
      res.json({ msg: "Login sucessfull..!!" });
    } catch (err) {
      return res.status(500).json({ msg: err.message });
    }
  },

  getAccessToken: (req, res) => {
    try {
      const rf_token = req.cookies.refreshtoken;

      if (!rf_token) return res.status(400).json({ msg: "Please login now!" });

      jwt.verify(rf_token, process.env.REFRESH_TOKEN_SECRET, (err, admin) => {
        if (err) return res.status(400).json({ msg: "Please login now!" });

        const access_token = createAccessToken({ id: admin.id });
        res.json({ access_token });
        // console.log(user)
      });
    } catch (err) {
      return res.status(500).json({ msg: err.message });
    }
  },

  logout: async (req, res) => {
    try {
        res.clearCookie('refreshtoken', {path : '/admin/refresh_token'})
        return res.json({msg: "Logged Out successfully..!!"})
    } catch (err) {
        return res.status(500).json({msg: err.message})
    }
},

    authExample: async(req,res) => {
        try{
            return res.json({msg: "Hello world | Middleware"})
        }catch (err) {
        return res.status(500).json({msg: err.message})
    }
    }
};

const validateEmail = (email) => {
  return email.match(
    /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
  );
};

const createAccessToken = (payload) => {
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
};

const createRefreshToken = (payload) => {
  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });
};

module.exports = userCtrl;
