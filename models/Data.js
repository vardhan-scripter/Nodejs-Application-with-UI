const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const dataSchema = new Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
});

module.exports = Data = mongoose.model("mydata", dataSchema);