# AllerSafe Recipe Admin Panel

A comprehensive Flask-based administrative panel for managing recipes and allergen information. This system allows administrators to oversee user accounts, review and moderate recipes, manage allergy data, and track system activities.

## Features

### 👤 Admin Management
- Secure admin authentication with password hashing
- Password reset functionality via SendGrid email
- Change password functionality
- Session management with "Remember Me" option
- Password visibility toggle on login forms

### 📊 Dashboard & Analytics
- Real-time statistics (user count, recipe count, active users)
- Recent activity overview
- System health monitoring

### 👥 User Management
- View all registered users
- Suspend/activate user accounts
- Delete user accounts
- Issue warnings to users with predefined guidelines
- Track user warnings and violations

### 🍽️ Recipe Management
- Review and moderate submitted recipes
- Approve/reject pending recipes
- Manage recipe status (active, suspended, rejected)
- Delete inappropriate recipes
- Advanced allergy filtering system
- Recipe-allergen association management

### ⚠️ Allergy Management
- Comprehensive allergy database with cross-reactivity information
- Filter recipes by allergen presence or absence
- Manage recipe-allergen relationships
- Support for multiple allergy categories (Fruits, Nuts & Seeds, Vegetables, Animal Products, etc.)

### 📋 Content Moderation
- Recipe reporting system
- Community guidelines management
- User warning system with severity levels
- Violation tracking

### 📝 Audit Logging
- Complete activity tracking for both admins and users
- Printable audit reports with professional formatting
- CSV export functionality
- Advanced filtering (admin-only, user-only actions)
- IP address tracking for security

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite3 with foreign key constraints
- **Frontend**: Bootstrap 5, Font Awesome icons
- **Email**: SendGrid API for password resets
- **Security**: Werkzeug password hashing
- **Environment**: python-dotenv for configuration

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd allersafe-admin-panel
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration**
   - Copy `.env.example` to `.env`
   - Configure your environment variables:
   ```bash
   SENDGRID_API_KEY=your_sendgrid_api_key_here
   FROM_EMAIL=your_email@example.com
   SECRET_KEY=your_secret_key_here
   ```

5. **Initialize Database**
   ```bash
   python database.py
   ```

6. **Upgrade Database (for new installations)**
   - Start the application and visit `/upgrade-db` once to add user tracking columns

7. **Run the application**
   ```bash
   python app.py
   ```

8. **Access the application**
   - Open your browser to `http://localhost:5000`
   - Use default admin credentials:
     - Username: `admin1`, Password: `password1`
     - Username: `admin2`, Password: `password2`
     - Username: `admin3`, Password: `password3`

## Configuration

### Environment Variables
- `SENDGRID_API_KEY`: Your SendGrid API key for email functionality
- `FROM_EMAIL`: Email address for sending password reset emails
- `SECRET_KEY`: Flask secret key for session security

### Database Schema
The application automatically creates and manages the following tables:
- `admins`: Administrator accounts
- `users`: Regular user accounts
- `recipes`: Recipe data with author relationships
- `allergies`: Allergen information with cross-reactivity data
- `recipe_allergies`: Many-to-many relationship between recipes and allergens
- `audit_log`: System activity tracking
- `guidelines`: Community guidelines for moderation
- `user_warnings`: Warning system for user violations
- `recipe_reports`: User-submitted recipe reports
- `password_reset_tokens`: Secure password reset functionality

## Usage

### Admin Functions

1. **Dashboard**: Overview of system statistics and recent activities
2. **User Management**: Manage user accounts, suspensions, and warnings
3. **Recipe Management**: Review, approve, reject, and manage recipes
4. **Pending Recipes**: Queue of recipes awaiting approval
5. **Allergy Management**: Configure allergen information and recipe associations
6. **Guidelines**: Create and manage community guidelines
7. **Reports**: Handle user-submitted recipe reports
8. **Audit Log**: Track all system activities with export capabilities

### Security Features

- Password hashing using Werkzeug
- Session management with secure cookies
- CSRF protection through Flask's built-in mechanisms
- IP address logging for audit trails
- Secure password reset with time-limited tokens

### Audit & Compliance

- Complete activity logging for admins and users
- Professional printable reports
- CSV export for external analysis
- Filtering and search capabilities
- Compliance-ready documentation

## API Endpoints

### Authentication
- `GET/POST /login`: Admin login
- `GET /logout`: Admin logout
- `GET/POST /forgot-password`: Password reset request
- `GET/POST /reset-password/<token>`: Password reset with token
- `GET/POST /change-password`: Change current password

### Dashboard & Management
- `GET /dashboard`: Main dashboard
- `GET /user-management`: User administration
- `GET /recipe-management`: Recipe administration
- `GET /pending-recipes`: Recipe approval queue
- `GET /audit-log`: System activity log

### User Actions
- `GET /suspend-user/<id>`: Suspend user account
- `GET /activate-user/<id>`: Activate user account
- `GET /delete-user/<id>`: Delete user account
- `GET/POST /warn-user/<id>`: Issue user warning

### Recipe Actions
- `GET /approve-recipe/<id>`: Approve pending recipe
- `GET /reject-recipe/<id>`: Reject pending recipe
- `GET /suspend-recipe/<id>`: Suspend active recipe
- `GET /activate-recipe/<id>`: Activate suspended recipe
- `GET /delete-recipe/<id>`: Delete recipe

## Development

### Database Migrations
- Run `/upgrade-db` route after updating schema
- Backup database before major changes
- Test migrations on development data first

### Adding New Features
1. Update database schema in `database.py`
2. Create migration function for existing installations
3. Add route handlers in `app.py`
4. Create/update templates as needed
5. Update audit logging for new actions

## Security Considerations

- Never commit `.env` files to version control
- Regularly update dependencies for security patches
- Monitor audit logs for suspicious activities
- Use strong passwords for admin accounts
- Keep SendGrid API keys secure and rotate regularly

## Troubleshooting

### Common Issues

1. **Database Errors**: Ensure database is initialized and upgraded
2. **Email Not Sending**: Check SendGrid API key and FROM_EMAIL configuration
3. **Template Errors**: Ensure all templates exist in `templates/` directory
4. **Permission Issues**: Check file permissions for database and static files

### Database Recovery
```bash
# Backup current database
cp admin_panel.db admin_panel.db.backup

# Reinitialize if corrupted
python database.py
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For technical support or questions about this admin panel, please refer to the documentation or create an issue in the project repository.

---

**Note**: This is an administrative panel for managing recipe and allergen data. Ensure proper security measures are in place before deploying to production environments.
