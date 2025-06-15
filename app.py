from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import uuid
import json
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wecare_incidents.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# Database Models
class Department(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    users = db.relationship('User', backref='department', lazy=True)
    incidents = db.relationship('Incident', backref='department', lazy=True)

class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='citizen')  # admin, governor, officer, citizen
    department_id = db.Column(db.String(36), db.ForeignKey('department.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    assigned_incidents = db.relationship('Incident', foreign_keys='Incident.assigned_to', backref='assignee', lazy=True)
    created_assignments = db.relationship('Incident', foreign_keys='Incident.assigned_by', backref='assigner', lazy=True)
    incident_updates = db.relationship('IncidentUpdate', backref='user', lazy=True)
    assignments_made = db.relationship('IncidentAssignment', foreign_keys='IncidentAssignment.assigned_by', backref='assigner', lazy=True)
    assignments_received = db.relationship('IncidentAssignment', foreign_keys='IncidentAssignment.assigned_to', backref='assignee', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Incident(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False, default='general')
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(500), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, in_progress, resolved, closed
    priority = db.Column(db.String(20), nullable=False, default='medium')  # low, medium, high, urgent
    reporter_name = db.Column(db.String(100), nullable=True)
    reporter_contact = db.Column(db.String(100), nullable=True)
    photos = db.Column(db.Text, nullable=True)  # JSON string of photo filenames
    assigned_to = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    assigned_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    department_id = db.Column(db.String(36), db.ForeignKey('department.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assignments = db.relationship('IncidentAssignment', backref='incident', lazy=True, cascade='all, delete-orphan')
    updates = db.relationship('IncidentUpdate', backref='incident', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'address': self.address,
            'status': self.status,
            'priority': self.priority,
            'reporter_name': self.reporter_name,
            'reporter_contact': self.reporter_contact,
            'photos': json.loads(self.photos) if self.photos else [],
            'assigned_to': self.assigned_to,
            'assigned_by': self.assigned_by,
            'department_id': self.department_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class IncidentAssignment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = db.Column(db.String(36), db.ForeignKey('incident.id'), nullable=False)
    assigned_to = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    assigned_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)

class IncidentUpdate(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = db.Column(db.String(36), db.ForeignKey('incident.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    status_from = db.Column(db.String(20), nullable=True)
    status_to = db.Column(db.String(20), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            user = User.query.get(session['user_id'])
            if not user or user.role not in roles:
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_incidents(user):
    """Get incidents based on user role and department"""
    if user.role == 'admin':
        # Admin can see all incidents
        return Incident.query.order_by(Incident.created_at.desc()).all()
    elif user.role == 'governor':
        # Governor can see all incidents
        return Incident.query.order_by(Incident.created_at.desc()).all()
    elif user.role == 'officer':
        # Officer can only see incidents from their department or assigned to them
        if user.department_id:
            return Incident.query.filter(
                (Incident.department_id == user.department_id) | 
                (Incident.assigned_to == user.id)
            ).order_by(Incident.created_at.desc()).all()
        else:
            return Incident.query.filter_by(assigned_to=user.id).order_by(Incident.created_at.desc()).all()
    else:
        # Citizens can see all incidents (public view)
        return Incident.query.order_by(Incident.created_at.desc()).all()

def get_department_officers(department_id):
    """Get officers from a specific department"""
    return User.query.filter_by(role='officer', department_id=department_id, is_active=True).all()

# Template context processor
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return {'current_user': user}

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email, is_active=True).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user_role'] = user.role
            flash(f'Welcome back, {user.full_name}!', 'success')
            
            # Redirect based on role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'governor':
                return redirect(url_for('governor_dashboard'))
            elif user.role == 'officer':
                return redirect(url_for('officer_dashboard'))
            else:
                return redirect(url_for('citizen_dashboard'))
        else:
            flash('Invalid email or password, or account is disabled.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/citizen')
def citizen_dashboard():
    incidents = Incident.query.order_by(Incident.created_at.desc()).all()
    return render_template('citizen_dashboard.html', incidents=incidents)

@app.route('/admin')
@role_required('admin')
def admin_dashboard():
    user = User.query.get(session['user_id'])
    incidents = get_user_incidents(user)
    users = User.query.filter_by(is_active=True).all()
    departments = Department.query.all()
    assignments = IncidentAssignment.query.all()
    
    stats = {
        'total_incidents': len(incidents),
        'pending_incidents': len([i for i in incidents if i.status == 'pending']),
        'in_progress_incidents': len([i for i in incidents if i.status == 'in_progress']),
        'resolved_incidents': len([i for i in incidents if i.status == 'resolved']),
        'total_users': len(users),
        'officers': len([u for u in users if u.role == 'officer']),
        'governors': len([u for u in users if u.role == 'governor']),
        'total_departments': len(departments)
    }
    
    return render_template('admin_dashboard.html', 
                         current_user=user, 
                         incidents=incidents, 
                         users=users, 
                         departments=departments, 
                         assignments=assignments,
                         stats=stats)

@app.route('/admin/users')
@role_required('admin')
def admin_users():
    users = User.query.filter_by(is_active=True).all()
    departments = Department.query.all()
    return render_template('admin_users.html', users=users, departments=departments)

@app.route('/admin/departments')
@role_required('admin')
def admin_departments():
    departments = Department.query.all()
    return render_template('admin_departments.html', departments=departments)

@app.route('/governor')
@role_required('governor')
def governor_dashboard():
    user = User.query.get(session['user_id'])
    incidents = get_user_incidents(user)
    officers = User.query.filter_by(role='officer', is_active=True).all()
    departments = Department.query.all()
    assignments = IncidentAssignment.query.all()
    
    stats = {
        'total_incidents': len(incidents),
        'pending_incidents': len([i for i in incidents if i.status == 'pending']),
        'in_progress_incidents': len([i for i in incidents if i.status == 'in_progress']),
        'resolved_incidents': len([i for i in incidents if i.status == 'resolved']),
        'total_officers': len(officers),
        'active_assignments': len(assignments),
        'department_count': len(departments)
    }
    
    return render_template('governor_dashboard.html', 
                         current_user=user, 
                         incidents=incidents, 
                         officers=officers, 
                         departments=departments,
                         stats=stats)

@app.route('/officer')
@role_required('officer')
def officer_dashboard():
    user = User.query.get(session['user_id'])
    # Officers see only their assigned incidents and department incidents
    assigned_incidents = get_user_incidents(user)
    
    return render_template('officer_dashboard.html', 
                         current_user=user, 
                         assigned_incidents=assigned_incidents)

# API Routes
@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        incidents = get_user_incidents(user)
    else:
        incidents = Incident.query.order_by(Incident.created_at.desc()).all()
    
    return jsonify([incident.to_dict() for incident in incidents])

@app.route('/api/incidents', methods=['POST'])
def create_incident():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not all(key in data for key in ['title', 'description', 'latitude', 'longitude']):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Create new incident
        incident = Incident(
            title=data['title'],
            description=data['description'],
            category=data.get('category', 'general'),
            latitude=float(data['latitude']),
            longitude=float(data['longitude']),
            address=data.get('address'),
            reporter_name=data.get('reporter_name'),
            reporter_contact=data.get('reporter_contact'),
            photos=json.dumps(data.get('photos', []))
        )
        
        db.session.add(incident)
        db.session.commit()
        
        return jsonify(incident.to_dict()), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents/<incident_id>', methods=['PUT'])
def update_incident(incident_id):
    try:
        incident = Incident.query.get_or_404(incident_id)
        data = request.get_json()
        
        # Check permissions
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user.role == 'officer' and user.department_id != incident.department_id and incident.assigned_to != user.id:
                return jsonify({'error': 'Access denied'}), 403
        
        # Store old status for update tracking
        old_status = incident.status
        
        # Update allowed fields
        if 'status' in data:
            incident.status = data['status']
        if 'priority' in data:
            incident.priority = data['priority']
        if 'category' in data:
            incident.category = data['category']
        if 'assigned_to' in data:
            incident.assigned_to = data['assigned_to']
        if 'assigned_by' in data:
            incident.assigned_by = data['assigned_by']
        if 'department_id' in data:
            incident.department_id = data['department_id']
            
        incident.updated_at = datetime.utcnow()
        
        # Create update record if status changed
        if 'status' in data and old_status != data['status']:
            update = IncidentUpdate(
                incident_id=incident.id,
                user_id=session.get('user_id'),
                status_from=old_status,
                status_to=data['status'],
                notes=data.get('notes', '')
            )
            db.session.add(update)
        
        db.session.commit()
        
        return jsonify(incident.to_dict())
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/assign_incident', methods=['POST'])
@role_required('admin', 'governor')
def assign_incident():
    try:
        data = request.get_json()
        incident_id = data['incident_id']
        assigned_to = data['assigned_to']
        notes = data.get('notes', '')
        department_id = data.get('department_id')
        
        # Update incident
        incident = Incident.query.get_or_404(incident_id)
        incident.assigned_to = assigned_to
        incident.assigned_by = session['user_id']
        incident.status = 'in_progress'
        incident.updated_at = datetime.utcnow()
        
        # Set department if provided
        if department_id:
            incident.department_id = department_id
        
        # Create assignment record
        assignment = IncidentAssignment(
            incident_id=incident_id,
            assigned_to=assigned_to,
            assigned_by=session['user_id'],
            notes=notes
        )
        
        # Create update record
        update = IncidentUpdate(
            incident_id=incident_id,
            user_id=session['user_id'],
            status_from='pending',
            status_to='in_progress',
            notes=f'Assigned to officer. {notes}' if notes else 'Assigned to officer.'
        )
        
        db.session.add(assignment)
        db.session.add(update)
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['POST'])
@role_required('admin')
def create_user():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'full_name', 'role', 'password']
        if not all(key in data for key in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check if email already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        # Create new user
        user = User(
            email=data['email'],
            full_name=data['full_name'],
            role=data['role'],
            department_id=data.get('department_id')
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role,
                'department_id': user.department_id
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
@role_required('admin')
def update_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        # Update allowed fields
        if 'full_name' in data:
            user.full_name = data['full_name']
        if 'email' in data:
            # Check if email already exists for another user
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user.id:
                return jsonify({'error': 'Email already exists'}), 400
            user.email = data['email']
        if 'role' in data:
            user.role = data['role']
        if 'department_id' in data:
            user.department_id = data['department_id']
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['DELETE'])
@role_required('admin')
def deactivate_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user.is_active = False
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/departments', methods=['POST'])
@role_required('admin')
def create_department():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({'error': 'Department name is required'}), 400
        
        # Check if department already exists
        if Department.query.filter_by(name=data['name']).first():
            return jsonify({'error': 'Department already exists'}), 400
        
        # Create new department
        department = Department(
            name=data['name'],
            description=data.get('description', '')
        )
        
        db.session.add(department)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'department': {
                'id': department.id,
                'name': department.name,
                'description': department.description
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/departments/<department_id>/officers')
def get_department_officers_api(department_id):
    officers = get_department_officers(department_id)
    return jsonify([{
        'id': officer.id,
        'full_name': officer.full_name,
        'email': officer.email
    } for officer in officers])

@app.route('/api/incident_updates/<incident_id>')
def get_incident_updates(incident_id):
    # Check permissions
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        incident = Incident.query.get_or_404(incident_id)
        
        if user.role == 'officer' and user.department_id != incident.department_id and incident.assigned_to != user.id:
            return jsonify({'error': 'Access denied'}), 403
    
    updates = IncidentUpdate.query.filter_by(incident_id=incident_id).order_by(IncidentUpdate.created_at.desc()).all()
    
    updates_data = []
    for update in updates:
        updates_data.append({
            'id': update.id,
            'user_name': update.user.full_name if update.user else 'System',
            'status_from': update.status_from,
            'status_to': update.status_to,
            'notes': update.notes,
            'created_at': update.created_at.isoformat()
        })
    
    return jsonify(updates_data)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to avoid conflicts
            filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            return jsonify({'filename': filename, 'url': f'/static/uploads/{filename}'})
        
        return jsonify({'error': 'Invalid file type'}), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_tables():
    """Create database tables and insert default data"""
    with app.app_context():
        db.create_all()
        
        # Create default departments
        departments_data = [
            ('Public Works', 'Road maintenance, utilities, infrastructure'),
            ('Public Safety', 'Police, fire, emergency services'),
            ('Environmental Services', 'Waste management, environmental issues'),
            ('Parks & Recreation', 'Parks, recreational facilities, green spaces'),
            ('Transportation', 'Traffic, public transport, road safety'),
            ('Health Services', 'Public health, sanitation, health emergencies')
        ]
        
        for name, description in departments_data:
            if not Department.query.filter_by(name=name).first():
                dept = Department(name=name, description=description)
                db.session.add(dept)
        
        # Create default admin user
        if not User.query.filter_by(email='admin@city.gov').first():
            admin = User(
                email='admin@city.gov',
                full_name='System Administrator',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
        
        # Create default governor user
        if not User.query.filter_by(email='governor@city.gov').first():
            governor = User(
                email='governor@city.gov',
                full_name='City Governor',
                role='governor'
            )
            governor.set_password('governor123')
            db.session.add(governor)
        
        db.session.commit()
        print("Database tables created and default data inserted successfully!")

if __name__ == '__main__':
    # Create tables before running the app
    create_tables()
    print("Starting WeCare Municipal Incident Management System...")
    print("Developed by The Mapper Co.,Ltd.")
    print("Visit: http://localhost:5000")
    print("\nDefault Login Credentials:")
    print("Administrator: admin@city.gov / admin123")
    print("Governor: governor@city.gov / governor123")
    app.run(debug=True, host='0.0.0.0', port=5000)

    from flask import Flask

    app = Flask(__name__)


    @app.route("/")
    def home():
        return "WeCare is running on Render!"

    # Make sure this is NOT included on Render
    # if __name__ == "__main__":
    #     app.run(debug=True)
