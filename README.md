# School Bus Tracker Server

A comprehensive school bus tracking API server with multi-tenant support, real-time location tracking, and attendance management.

## Features

- 🏫 Multi-school/tenant support
- 🚌 Real-time bus tracking with GPS
- 👨‍✈️ Driver management and assignments
- 👨‍👩‍👧‍👦 Parent and student management
- 📍 Route planning with stops
- ✅ Attendance tracking
- 🔐 Role-based access control (Admin, School, School Users, Drivers, Parents)
- 📱 Mobile-friendly API
- 📝 Complete API documentation with Swagger

## Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0

## Local Development Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure environment variables:**
   - Copy `env.example` to `.env`
   - Update the values, especially `JWT_SECRET`
   ```bash
   cp env.example .env
   ```

3. **Initialize database:**
   ```bash
   npm run migrate
   ```
   This creates the SQLite database and seeds a default admin account.

4. **Start the development server:**
   ```bash
   npm run dev
   ```
   Server will run at: http://localhost:4000

5. **Access API Documentation:**
   - Swagger UI: http://localhost:4000/api/docs

## Default Credentials

- **Admin:** `admin` / `admin123`

## Heroku Deployment

### Step 1: Prepare Your Repository

1. Make sure all changes are committed:
   ```bash
   git add .
   git commit -m "Prepare for Heroku deployment"
   ```

### Step 2: Create Heroku App

1. Install Heroku CLI from: https://devcenter.heroku.com/articles/heroku-cli

2. Login to Heroku:
   ```bash
   heroku login
   ```

3. Create a new Heroku app:
   ```bash
   heroku create your-app-name
   ```

### Step 3: Configure Environment Variables

Set required environment variables on Heroku:

```bash
heroku config:set JWT_SECRET="your_super_secure_random_secret_key_here"
heroku config:set PORT=4000
heroku config:set SMTP_HOST="smtp.gmail.com"
heroku config:set SMTP_PORT=587
heroku config:set EMAIL_FROM="noreply@yourschool.com"
```

### Step 4: Deploy to Heroku

1. Push your code to Heroku:
   ```bash
   git push heroku main
   ```
   (or `git push heroku master` if your branch is master)

2. The database will be automatically created on first run.

3. Check logs to verify deployment:
   ```bash
   heroku logs --tail
   ```

4. Open your app:
   ```bash
   heroku open
   ```

### Step 5: Access Your API

Your API will be available at: `https://your-app-name.herokuapp.com`

- API Documentation: `https://your-app-name.herokuapp.com/api/docs`
- Health Check: `https://your-app-name.herokuapp.com/api/health`

## Important Notes for Production

### Database Considerations

- **SQLite Limitations on Heroku:** Heroku's ephemeral filesystem means SQLite data may be lost on dyno restart
- **Recommended for Production:** Use Heroku Postgres add-on for persistent storage
  ```bash
  heroku addons:create heroku-postgresql:mini
  ```
  Then modify `src/index.js` to use PostgreSQL instead of SQLite

### File Uploads

- Uploaded files (logos, banners) stored in `/uploads` will be lost on dyno restart
- **Recommended:** Use cloud storage (AWS S3, Cloudinary) for production
  ```bash
  heroku addons:create cloudinary:starter
  ```

### Security

- Always use a strong `JWT_SECRET` in production
- Enable HTTPS (Heroku provides this automatically)
- Consider rate limiting for API endpoints
- Regularly update dependencies

## API Endpoints

### Authentication
- `POST /api/auth/login` - Admin login
- `POST /api/auth/school-login` - School login
- `POST /api/auth/school-user-login` - School sub-user login
- `POST /api/auth/mobile-login` - Driver/Parent auto-detect login
- `POST /api/auth/driver-login` - Driver login
- `POST /api/auth/parent-login` - Parent login

### Main Resources
- `/api/schools` - School management
- `/api/drivers` - Driver management
- `/api/students` - Student management
- `/api/parents` - Parent management
- `/api/buses` - Bus management
- `/api/routes` - Route management
- `/api/assignments` - Driver/Bus assignments
- `/api/attendance` - Attendance tracking
- `/api/classes` - Class management

### Other
- `/api/dashboard/summary` - Dashboard statistics
- `/api/health` - Health check endpoint

For complete API documentation, visit `/api/docs` (Swagger UI)

## Scripts

- `npm start` - Start production server
- `npm run dev` - Start development server
- `npm run migrate` - Initialize database with tables
- `npm run reset-db` - Reset database to default state

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** SQLite3 (development), PostgreSQL recommended (production)
- **Authentication:** JWT (jsonwebtoken)
- **File Upload:** Multer
- **Documentation:** Swagger UI
- **Email:** Nodemailer

## Troubleshooting

### Common Issues

1. **Port already in use:**
   - Change PORT in `.env` file or kill the process using port 4000

2. **Database errors:**
   - Delete `app.db` and run `npm run migrate` again

3. **Heroku deployment fails:**
   - Check logs: `heroku logs --tail`
   - Ensure Node version matches engines in `package.json`
   - Verify all environment variables are set

4. **Swagger not loading:**
   - Ensure `docs/swagger.yaml` exists
   - Check console for YAML parsing errors

## Support

For issues and questions, please check the API documentation at `/api/docs` or review the source code.

## License

Private - Internal Use Only