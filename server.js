import express from "express";
import Database from "better-sqlite3";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { v4 as uuidv4, parse as uuidParse } from "uuid";
import sanitize from "sanitize-html";
import methodOverride from "method-override";
import { marked } from 'marked'

const db = new Database("ourApp.db");
db.pragma("journal_mode = WAL");

// database setup
const createTables = db.transaction(() => {
  db.prepare(
    `
        CREATE TABLE IF NOT EXISTS users(
            id BLOB PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
        `
  ).run();
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts(
      id BLOB PRIMARY KEY ,
      title TEXT NOT NULL,
      body  TEXT NOT NULL,
      createdDate TEXT,
      userId BLOB,
      FOREIGN KEY (userId) REFERENCES users(id)
    )`
  ).run();
});

createTables();

const app = express();
const PORT = process.env.PORT || 8000;

app.set("view engine", "ejs");
// serve static files in public
app.use(express.static("public"));
app.use(cookieParser());
// req parse middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
// override with POST having ?_method=DELETE
app.use(methodOverride("_method"));

app.use(function (req, res, next) {
  // markdown function
  res.locals.filterUserHTML = function (content) {
    return sanitize(marked.parse(content), { allowedTags: ["p", "br", "ul", "ol", "strong", "bold", "i", "em", "h1", "h2", "h3", "h4", "h5", "h6"], allowedAttributes: {} });
  };

  res.locals.errors = [];
  // try to decode incoming cookie
  try {
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWT_SECRET);
    const userprep = db.prepare(`SELECT * FROM users WHERE id=?`);
    const user = userprep.get(decoded.userId);
    req.user = user;
  } catch (error) {
    req.user = false;
  }
  res.locals.user = req.user;
  next();
});

// get homepage
app.get("/", (req, res) => {
  if (req.user) {
    const postsPrep = db.prepare(`SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.userId = users.id WHERE posts.userId=? ORDER BY posts.createdDate DESC`);
    const posts = postsPrep.all(req.user.id);
    return res.render("dashboard", { posts, username: req.user.username });
  }
  res.render("homepage");
});

// get login page
app.get("/login", (req, res) => {
  res.render("login");
});

// register new user contoller
app.post("/register", (req, res) => {
  const errors = [];
  const { username, password } = req.body;
  if (typeof username !== "string") req.body.username = "";
  if (typeof password !== "string") req.body.password = "";

  req.body.username = req.body.username.trim();
  if (!username) {
    errors.push("you must provide a username");
  }
  if (username && username.length < 3) {
    errors.push("username can not be less than 3 characters");
  }
  if (username && username.length > 20) {
    errors.push("username can not exceed 20 characters");
  }
  if (username && !username.match(/^[a-zA-Z0-9]+$/)) {
    errors.push("username can onlt contain letters and numbers");
  }
  if (!password) {
    errors.push("you must provide a password");
  }
  if (password && password.length < 8) {
    errors.push("password can not be less than 8 characters");
  }
  if (password && password.length > 18) {
    errors.push("password can not exceed 18 characters");
  }
  if (errors.length) {
    return res.render("homepage", { errors });
  }
  // check if user already exists
  const userExistsprep = db.prepare(`SELECT * FROM users WHERE username=?`);
  const userExists = userExistsprep.get(username);
  if (userExists) {
    errors.push("user already exists");
    return res.render("homepage", { errors });
  }
  // hash the password
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);
  // save the new user into the db
  // const uuidBuffer = Buffer.from(uuidParse(uuidv4()));
  const insertUser = db.prepare("INSERT INTO users (id,username,password) VALUES (?, ?, ?)");
  const result = insertUser.run(uuidv4(), username, hashedPassword);

  const lookupStatment = db.prepare("SELECT * FROM users WHERE ROWID = ?");
  const user = lookupStatment.get(result.lastInsertRowid);

  // log the user in by giving them a cookie
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: "24h" });
  res.cookie("ourSimpleApp", token, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 1000 * 60 * 60 * 24 });
  res.redirect("/");
});

// login controller
app.post("/login", (req, res) => {
  const errors = [];
  const { username, password } = req.body;
  if (typeof username !== "string") req.body.username = "";
  if (typeof password !== "string") req.body.password = "";

  if (!username || !password) {
    errors.push("you must provide a username and a password");
    return res.render("login", { errors });
  }

  const userExistsprep = db.prepare(`SELECT * FROM users WHERE username=?`);
  const user = userExistsprep.get(username);
  // check if user exists
  if (!user) {
    errors.push("user not found");
    return res.render("login", { errors });
  }
  // check if the password match
  const passwordMatch = bcrypt.compareSync(password, user.password);
  if (!passwordMatch) {
    errors.push("invalid credentials");
  }

  if (errors.length) {
    return res.render("login", { errors });
  }
  // generate token
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: "24h" });
  // set cookie
  res.cookie("ourSimpleApp", token, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 1000 * 60 * 60 * 24 });
  //    redirect
  res.redirect("/");
});

// logout controller
app.get("/logout", (req, res) => {
  // clear the token and refresh
  res.clearCookie("ourSimpleApp");
  res.redirect("/");
});

// CRUD

// logged in check utility function
function mustBeLoggedIn(req, res, next) {
  if (req.user) {
    return next();
  }
  return res.redirect("/");
}

// redirect to createpost view
app.get("/createPost", mustBeLoggedIn, (req, res) => {
  res.render("createPost");
});

// post validation utility function
function sharedPostValidation(req) {
  const errors = [];
  if (typeof req.body.title !== "string") req.body.title = "";
  if (typeof req.body.body !== "string") req.body.body = "";

  // trim - sanitize or strip out html
  req.body.title = sanitize(req.body.title.trim(), { allowedTags: [], allowedAttributes: {} });
  req.body.body = sanitize(req.body.body.trim(), { allowedTags: [], allowedAttributes: {} });

  const { title, body } = req.body;
  if (!title || !body) {
    errors.push("post title or body is empty");
    return errors;
  }
  if (title.length < 1 || title.length > 50) {
    errors.push("title must be between 1 and 50 charcters");
  }
  return errors;
}

// add a post contoller
app.post("/createPost", mustBeLoggedIn, (req, res) => {
  const { title, body } = req.body;
  const errors = sharedPostValidation(req);
  if (errors.length) {
    return res.render("createPost", { errors });
  }
  // save post body and create a new post in the db using the userId as foreign key
  const postPrep = db.prepare(`
    INSERT INTO posts (id, title, body, createdDate, userId) VALUES (?,?,?,?,?)
    `);
  const result = postPrep.run(uuidv4(), title, body, new Date().toISOString(), req.user.id);

  const getPostPrep = db.prepare(`
    SELECT * FROM posts WHERE ROWID=?
    `);
  const post = getPostPrep.get(result.lastInsertRowid);
  res.redirect(`/post/${post.id}`);
});

// get a post by id
app.get("/post/:id", mustBeLoggedIn, (req, res) => {
  // the sql query will fetch the post along with the username
  const getPostPrep = db.prepare(`
    SELECT posts.*,users.username FROM posts INNER JOIN users ON posts.userId=users.id WHERE posts.id=?
    `);
  const post = getPostPrep.get(req.params.id);
  if (!post) {
    return res.redirect("/");
  }
  const isAuthor = post.userId === req.user.id;
  res.render("singlePost", { post, isAuthor });
});

// update post view
app.get("/updatePost/:id", mustBeLoggedIn, (req, res) => {
  const getPostPrep = db.prepare(`
    SELECT posts.*,users.username FROM posts INNER JOIN users ON posts.userId=users.id WHERE posts.id=?
    `);
  const post = getPostPrep.get(req.params.id);
  if (!post) {
    return res.redirect("/");
  }
  // we must check that the userId of the post matches the req user's id
  if (post.userId !== req.user.id) {
    return res.render("unAuthorized");
  }

  res.render("updatePost", { post });
});
// update post controller
app.patch("/updatePost/:id", mustBeLoggedIn, (req, res) => {
  let errors = [];
  const { title, body } = req.body;
  // get old post
  const postPrep = db.prepare(`SELECT * FROM posts WHERE id=?`);
  const oldPost = postPrep.get(req.params.id);
  // user verify
  if (oldPost.userId !== req.user.id) {
    return res.render("unAuthorized");
  }

  errors = sharedPostValidation(req);
  if (errors.length) {
    return res.render("updatePost", { post: oldPost, errors });
  }
  if (oldPost.title === title && oldPost.body === body) {
    errors.push("no changes made");
    return res.render("updatePost", { post: oldPost, errors });
  }

  // update post
  const updatePrep = db.prepare(`UPDATE posts SET title=?,body=? WHERE id=?`);
  const updatedPost = updatePrep.run(title || oldPost.title, body || oldPost.body, req.params.id);

  res.redirect(`/post/${updatedPost.id}`);
});

// delete post controller
app.delete("/deletePost/:id", mustBeLoggedIn, (req, res) => {
  const postPrep = db.prepare(`SELECT * FROM posts WHERE id = ?`);
  const postToDelete = postPrep.get(req.params.id);
  console.log(postToDelete);
  if (!postToDelete) {
    return res.render("notFound");
  }
  // verify user
  if (postToDelete.userId !== req.user.id) {
    return res.render("unAuthorized");
  }
  // delete post
  const deletePostPrep = db.prepare(`DELETE FROM posts WHERE id = ?`);
  const deletePost = deletePostPrep.run(req.params.id);
  res.redirect("/");
});

app.listen(PORT, () => {
  console.log(`server is running on port ${PORT}`);
});
