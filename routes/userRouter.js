const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth");
const User = require("../models/userModel");

router.post("/register", async (req, res) => {
    try {
        const { email, password, displayName } = req.body;

        if (!email || !password)
            return res.status(400).json({msg: "Not all fields have been entered."});
        if (password.length < 6)
            return res.status(400).json({msg: "Password too short!"});

        const existingUser = await User.findOne({ email: email });
        
        if (existingUser)
            return res.status(400).json({msg: "An account with this email already exists."});
        
        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password, salt);
        
        const newUser = new User({
            email: email,
            password: passwordHash,
            displayName: displayName? displayName : email
        });

        const savedUser = await newUser.save();
        res.json({id: savedUser._id, displayName: savedUser.displayName});
        
    } catch (err) {
        res.status(500).json({err: err.message});
    }
});

router.get("/getuser", async (req, res) => {
    try {
        const email = req.header("email");
        const displayName = req.header("displayName");

        if (!email && !displayName) {
            return res.status(400).json({msg: "Bad request"});
        }

        else {
            const user = await User.findOne(email? {email: email}: {displayName: displayName});
            return res.json(!user);
        }

    } catch (err) {
        res.status(500).json({err: err.message});
    }
});

router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password)
            return res.status(400).json({msg: "Not all fields are filled."});
        const user = await User.findOne({ email: email });
        if (!user)
            return res.status(400).json({msg: "User doesn't exist"});
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
            return res.status(400).json({msg: "Password error."});
        
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        return res.json({
            token,
            user: {
                id: user._id,
                displayName: user.displayName
            }
        });
    } catch (err) {
        res.status(500).json({err: err.message});
    }
});

router.delete("/delete", auth, async (req, res) => {
    try {
        const deletedUser = await User.findByIdAndDelete(req.user);
        if (!deletedUser)
            return res.status(401).json({msg: "User is already not existed"});
        res.json(deletedUser);
    } catch (err) {
        return res.status(500).json({err: err.message});
    }
});

router.post("/tokenIsValid", async (req, res) => {
    try {
        const token = req.header("x-auth-token");
        if (!token) return res.json(false);

        const verified = jwt.verify(token, process.env.JWT_SECRET);
        if (!verified) return res.json(false);

        const user = await User.findById(verified.id);
        if (!user) return res.json(false);
        return res.json(true);
        
    } catch (err) {
        return res.status(500).json({err: err.message});
    }
});

router.get("/", auth, async (req, res) => {
    const user = await User.findById(req.user);
    res.json({
        id: user._id,
        displayName: user.displayName
    });
});

module.exports = router;