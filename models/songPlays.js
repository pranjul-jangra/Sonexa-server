import mongoose from 'mongoose';

const songPlaySchema = new mongoose.Schema({
  musicId: { type: String, required: true, index: true },
  visitorId: { type: String, required: true, index: true },
  playedAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

songPlaySchema.index({ musicId: 1, visitorId: 1 }, { unique: true });


const songPlaysModal = mongoose.model("SongPlay", songPlaySchema);
export default songPlaysModal;
