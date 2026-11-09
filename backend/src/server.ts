import http from 'http';
import app from './app';

const port = process.env.PORT

async function runServer() {
  const server = http.createServer(app);
  server.listen(port, ()=> {
    console.log('server is running on port:', port);
  });
}

runServer().catch(err => {
  console.error(err);
  process.exit(1);
});