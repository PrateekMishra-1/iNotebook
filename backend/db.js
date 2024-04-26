const mongoose = require("mongoose")

async function connectToMongo() {
    try {
        // Connect to MongoDB with updated options
        await mongoose.connect('mongodb://localhost:27017/inotebook', {
            
        });
        console.log('Connected to MongoDB');
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
    }
}

module.exports = connectToMongo;