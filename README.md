# WeCare - Municipal Incident Management System

A comprehensive incident reporting and management platform designed for municipal governments with role-based access control and department-specific workflows.

## Features

### For Citizens
- **Public Incident Reporting**: Report incidents without requiring login
- **Photo Upload**: Attach multiple photos to incident reports
- **Interactive Maps**: Select incident location using Leaflet maps
- **Status Tracking**: View real-time status updates on submitted reports
- **Responsive Design**: Mobile-friendly interface for reporting on-the-go

### For Municipal Staff
- **Role-Based Access Control**: Different interfaces for Administrators, Governors, and Officers
- **Secure Authentication**: Email/password login with Supabase Auth
- **Department Management**: Organize staff by municipal departments

### For Administrators
- **System Overview**: Complete dashboard with incident statistics
- **User Management**: Manage staff accounts and department assignments
- **Department Administration**: Create and manage municipal departments
- **Incident Assignment**: Assign incidents to appropriate departments and officers
- **Comprehensive Reporting**: Track performance across all departments

### For Governors
- **Municipal Overview**: High-level view of all incidents and departments
- **Incident Assignment**: Assign unassigned incidents to officers
- **Department Monitoring**: Track performance of different departments
- **Officer Management**: View and manage officers across departments
- **Progress Tracking**: Monitor incident resolution progress

### For Officers
- **Personal Dashboard**: View assigned incidents and tasks
- **Status Updates**: Update incident status and add progress notes
- **Incident History**: Track all updates and changes to assigned incidents
- **Department Focus**: Work within specific department context
- **Mobile-Friendly**: Update incidents from field using mobile devices

## System Architecture

### User Roles
1. **Citizens**: Can report incidents and view public information
2. **Officers**: Department staff who handle and resolve incidents
3. **Governors**: Municipal leaders who oversee departments and assignments
4. **Administrators**: System administrators with full access

### Database Schema
- **incidents**: Core incident data with location, status, and assignments
- **users**: Extended user profiles with roles and department assignments
- **departments**: Municipal departments (Public Works, Safety, etc.)
- **incident_assignments**: Track incident assignments between users
- **incident_updates**: Audit trail of all status changes and updates

### Technology Stack
- **Frontend**: React + TypeScript + Tailwind CSS
- **Backend**: Supabase (PostgreSQL + Auth + Storage)
- **Maps**: Leaflet.js for interactive mapping
- **Icons**: Lucide React for consistent iconography
- **Deployment**: Vite for development and building

## Installation & Setup

### Prerequisites
- Node.js 18+ and npm
- Supabase account and project

### 1. Clone and Install
```bash
git clone <repository-url>
cd wecare-municipal-system
npm install
```

### 2. Supabase Setup
1. Create a new Supabase project
2. Click "Connect to Supabase" in the application
3. Run the database migrations to set up tables and policies
4. Create your first administrator account through the Supabase dashboard

### 3. Environment Variables
Create a `.env` file with your Supabase credentials:
```env
VITE_SUPABASE_URL=your-supabase-url
VITE_SUPABASE_ANON_KEY=your-supabase-anon-key
```

### 4. Run Development Server
```bash
npm run dev
```

## Initial Setup

### Creating Your First Administrator
1. Go to your Supabase project dashboard
2. Navigate to Authentication > Users
3. Create a new user with your admin email and password
4. Go to the SQL Editor and run:
```sql
INSERT INTO users (id, email, full_name, role)
VALUES (
  'your-auth-user-id',
  'admin@yourdomain.com',
  'Your Name',
  'admin'
);
```

### Setting Up Departments
Administrators can create departments through the admin dashboard or by inserting into the database:
```sql
INSERT INTO departments (name, description) VALUES
  ('Public Works', 'Road maintenance, utilities, infrastructure'),
  ('Public Safety', 'Police, fire, emergency services'),
  ('Environmental Services', 'Waste management, environmental issues');
```

## Usage Guide

### For Citizens
1. Visit the application homepage
2. Click "Report Incident" to submit a new incident
3. Fill in incident details, select location on map, and upload photos
4. Submit the report and receive a confirmation
5. Use "View Reports" to track status of submitted incidents

### For Municipal Staff
1. Click "Staff Login" in the header
2. Sign in with your municipal email and password
3. Access role-specific dashboard based on your permissions
4. Manage incidents according to your role responsibilities

### Incident Workflow
1. **Citizen Reports**: Citizens submit incidents through public interface
2. **Governor Assignment**: Governors review and assign incidents to appropriate officers
3. **Officer Processing**: Officers update status and work on resolution
4. **Status Updates**: All stakeholders can track progress through status updates
5. **Resolution**: Officers mark incidents as resolved when completed

## Customization

### Adding Departments
Administrators can add new departments through the admin dashboard or by updating the database directly.

### Configuring Categories
Incident categories can be customized in the ReportForm component to match your municipality's needs.

### Styling
The application uses Tailwind CSS for styling. Customize the design by modifying the Tailwind classes throughout the components.

### Maps Configuration
Default map location can be changed in the LocationMap component to center on your municipality.

## Security Features

- **Row Level Security (RLS)**: Database-level security ensuring users only access appropriate data
- **Role-Based Access Control**: Different permissions for each user role
- **Secure Authentication**: Supabase Auth handles password hashing and session management
- **Input Validation**: Client and server-side validation for all user inputs
- **File Upload Security**: Secure photo upload with type and size restrictions

## Production Deployment

### Database
- Use Supabase production environment
- Set up proper backup and monitoring
- Configure appropriate RLS policies for your organization

### Frontend
- Build the application: `npm run build`
- Deploy to your preferred hosting platform (Netlify, Vercel, etc.)
- Configure environment variables for production

### Security Considerations
- Use strong passwords for all accounts
- Regularly review user access and permissions
- Monitor incident data for sensitive information
- Implement proper data retention policies

## Support & Maintenance

### Regular Tasks
- Monitor incident volume and response times
- Review and update user accounts and permissions
- Backup incident data and photos
- Update system dependencies and security patches

### Troubleshooting
- Check Supabase logs for database errors
- Verify RLS policies for access issues
- Monitor photo storage usage and limits
- Review user feedback for system improvements

## License

This project is open source and available under the MIT License.

---

**Developed by The Mapper Co.,Ltd.**
*Geomatic Engineering • Software Engineering • Simulation Technology • Advanced Technology*