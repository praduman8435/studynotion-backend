const mongoose = require("mongoose");

// Define the Tags schema
const categorySchema = new mongoose.Schema({
	name: {
		type: String,
		required: false,
	},
	description: { type: String },
	// courses: [
	// 	{
	// 		type: mongoose.Schema.Types.ObjectId,
	// 		ref: "Course",
	// 	},
	// ],
});

// Export the Tags model
module.exports = mongoose.model("Category", categorySchema);