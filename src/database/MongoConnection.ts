import mongoose from 'mongoose';
import { MONGO_DB_CONNECTION_STRING } from '../utils/envConstants';

class MongoConnection {
  private static mongoConnectionInstance: MongoConnection;

  static getInstance(): MongoConnection {
    if (!this.mongoConnectionInstance) this.mongoConnectionInstance = new MongoConnection();
    return this.mongoConnectionInstance;
  }

  async startConnection(): Promise<void> {
    // const connParam: mongoose.ConnectOptions = { useUnifiedTopology: true };
    try {
      // eslint-disable-next-line max-len
      await mongoose.connect(MONGO_DB_CONNECTION_STRING);
      console.log('The app connected to the database succesfully!');
    } catch (err) {
      //   console.log(err);
      console.log('There was an error while connecting to the database!');
    }
  }
}

export default MongoConnection;
