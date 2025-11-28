# Heroku Deployment Checklist

## Prerequisites
- [ ] Heroku CLI installed
- [ ] Git repository initialized
- [ ] All code committed to git

## Deployment Steps

### 1. Install Heroku CLI
Download from: https://devcenter.heroku.com/articles/heroku-cli

### 2. Login to Heroku
```bash
heroku login
```

### 3. Create Heroku Application
```bash
# Create new app (choose a unique name)
heroku create your-bustracker-app-name

# Or if you want Heroku to generate a name
heroku create
```

### 4. Set Environment Variables
```bash
# Required variables
heroku config:set JWT_SECRET="your_super_secure_random_secret_key_change_this"
heroku config:set NODE_ENV="production"

# Optional email configuration
heroku config:set SMTP_HOST="smtp.gmail.com"
heroku config:set SMTP_PORT=587
heroku config:set EMAIL_FROM="noreply@yourschool.com"
```

### 5. Deploy Application
```bash
# Push to Heroku
git push heroku main

# Or if using master branch
git push heroku master
```

### 6. Verify Deployment
```bash
# Check deployment logs
heroku logs --tail

# Open application
heroku open

# Check health endpoint
curl https://your-app-name.herokuapp.com/api/health
```

### 7. Test API
Visit: `https://your-app-name.herokuapp.com/api/docs`

Test login with default credentials:
- Username: `admin`
- Password: `admin123`

## Post-Deployment Tasks

### Change Default Admin Password
1. Login to admin panel
2. Navigate to profile settings
3. Change password immediately

### Configure SMTP (Optional)
If you need email notifications:
```bash
heroku config:set SMTP_HOST="smtp.gmail.com"
heroku config:set SMTP_PORT=587
heroku config:set SMTP_USER="your-email@gmail.com"
heroku config:set SMTP_PASSWORD="your-app-password"
heroku config:set EMAIL_FROM="noreply@yourschool.com"
```

### Monitor Application
```bash
# View logs in real-time
heroku logs --tail

# Check dyno status
heroku ps

# Restart if needed
heroku restart
```

## Important Considerations

### ⚠️ SQLite Limitations on Heroku
- Heroku uses ephemeral filesystem
- Database may be lost on dyno restart/redeploy
- **Recommended:** Upgrade to PostgreSQL for production

### Upgrade to PostgreSQL (Recommended)
```bash
# Add PostgreSQL add-on
heroku addons:create heroku-postgresql:mini

# Get database URL
heroku config:get DATABASE_URL
```

Then update `src/index.js` to use PostgreSQL instead of SQLite.

### ⚠️ File Upload Limitations
- Uploaded files in `/uploads` directory will be lost on dyno restart
- **Recommended:** Use cloud storage (AWS S3, Cloudinary) for production

```bash
# Add Cloudinary for image storage
heroku addons:create cloudinary:starter

# Get Cloudinary URL
heroku config:get CLOUDINARY_URL
```

## Troubleshooting

### Application Crashes
```bash
# Check logs
heroku logs --tail --dyno=web

# Check dyno status
heroku ps

# Restart application
heroku restart
```

### Environment Variable Issues
```bash
# List all config vars
heroku config

# Set a variable
heroku config:set KEY=value

# Remove a variable
heroku config:unset KEY
```

### Build Failures
- Ensure `package.json` has correct Node version in `engines`
- Check for dependency conflicts
- Verify all required files are committed to git

### Database Issues
- SQLite database resets on each deploy
- Consider PostgreSQL for persistent data
- Use `heroku pg:backups:capture` for PostgreSQL backups

## Scaling (Optional)

### Upgrade Dyno Type
```bash
# View current dyno
heroku ps

# Scale to professional dyno
heroku ps:scale web=1:professional-1x
```

### Add-ons for Production
```bash
# PostgreSQL (persistent database)
heroku addons:create heroku-postgresql:mini

# Redis (caching)
heroku addons:create heroku-redis:mini

# Papertrail (log management)
heroku addons:create papertrail:choklad

# New Relic (monitoring)
heroku addons:create newrelic:wayne
```

## Security Checklist

- [ ] Changed default admin password
- [ ] Set strong JWT_SECRET
- [ ] Enabled HTTPS (automatic on Heroku)
- [ ] Configured CORS properly
- [ ] Set NODE_ENV=production
- [ ] No sensitive data in git repository
- [ ] Regular dependency updates

## Useful Commands

```bash
# View app info
heroku info

# Open app in browser
heroku open

# Open dashboard
heroku dashboard

# Run commands on Heroku
heroku run node src/migrate.js

# View environment variables
heroku config

# Tail logs
heroku logs --tail

# Restart app
heroku restart

# Scale dynos
heroku ps:scale web=1
```

## Support Resources

- Heroku Dev Center: https://devcenter.heroku.com
- Node.js on Heroku: https://devcenter.heroku.com/articles/getting-started-with-nodejs
- Heroku CLI Reference: https://devcenter.heroku.com/articles/heroku-cli-commands

## Maintenance

### Regular Tasks
- Monitor dyno usage and costs
- Review application logs
- Update dependencies monthly
- Backup database (if using PostgreSQL)
- Monitor API performance
- Review and rotate JWT secrets periodically

### Automated Backups (PostgreSQL)
```bash
# Schedule daily backups
heroku pg:backups:schedule DATABASE_URL --at '02:00 America/New_York'

# List backups
heroku pg:backups

# Download backup
heroku pg:backups:download
```
