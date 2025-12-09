const express = require('express');
const app = express();
const morgan = require('morgan');
const connectDB = require('./src/config/db');
const userRoutes = require('./src/routes/user.routes');
require('dotenv').config();
const PORT = process.env.PORT || 3000;



app.use(express.json());
app.use(morgan('dev'));

connectDB();


app.get('/', (req, res) => {
  res.send('Welcome to my Homepage!');
});


app.use('/api/users', userRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});