// hash_generator.js
const bcrypt = require('bcrypt');

const newPassword = 'admin@mit'; // The new admin password
const saltRounds = 10;

bcrypt.hash(newPassword, saltRounds, (err, hash) => {
  if (err) {
    console.error('Error generating hash:', err);
  } else {
    console.log('Your new ADMIN password hash is:');
    console.log(hash);
  }
});