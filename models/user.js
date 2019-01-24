const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');

const userSchema = new Schema({
    username: {
        type: String,
        required: [true, 'The username is required'],
        // unique: true
    },
    email: {
        type: String,
        required: [true, 'The email is required'],
        unique:true
    },
    firstName: {
        type:String
    },
    lastName: {
        type:String
    },
    // dob: {
    //     type: Date
    // },
    password: {
        type:String,
        required: [true, 'The password is required']
    },
    address: {
        type:String,
        required: [true, 'The address is required'],
        unique: true
    },
    country: {
        type:String
    },
    // city: {
    //     type:String
    // },
    // phoneNumber: {
    //     type:String
    // },
    seed: {
        type:String
    },
    created: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('User', userSchema);

/**
 * Compare the passed password with the value in the database. A model method.
 *
 * @param {string} password
 * @returns {object} callback
 */
userSchema.methods.comparePassword = function comparePassword(password, callback) {
    bcrypt.compare(password, this.password, callback);
};


/**
 * The pre-save hook method.
 */
userSchema.pre('save', function saveHook(next) {
    const user = this;

    // proceed further only if the password is modified or the user is new
    if (!user.isModified('password')) return next();


    return bcrypt.genSalt((saltError, salt) => {
        if (saltError) { return next(saltError); }

        return bcrypt.hash(user.password, salt, (hashError, hash) => {
            if (hashError) { return next(hashError); }

            // replace a password string with hash value
            user.password = hash;

            return next();
        });
    });
});