// frontend/src/components/Register.js
import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { register } from '../redux/slices/authSlice';
import { useNavigate, Link } from 'react-router-dom';

const Register = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { loading, error, token } = useSelector(state => state.auth);

  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
  });

  if (token) {
    navigate('/home');
  }

  const { name, email, password } = formData;

  const onChange = e => setFormData({ ...formData, [e.target.name]: e.target.value });

  const onSubmit = async e => {
    e.preventDefault();
    dispatch(register({ name, email, password }))
      .unwrap()
      .then(() => navigate('/home'))
      .catch(() => {});
  };

  return (
    <div>
      <h2>Register</h2>
      {error && <p style={{color:'red'}}>{error}</p>}
      <form onSubmit={onSubmit}>
        <div>
          <label>Name:</label>
          <input type="text" name="name" value={name} onChange={onChange} required />
        </div>
        <div>
          <label>Email:</label>
          <input type="email" name="email" value={email} onChange={onChange} required />
        </div>
        <div>
          <label>Password:</label>
          <input type="password" name="password" value={password} onChange={onChange} required />
        </div>
        <button type="submit" disabled={loading}>{loading ? 'Registering...' : 'Register'}</button>
      </form>
      <p>
        Already have an account? <Link to="/">Login Here</Link>
      </p>
    </div>
  );
};

export default Register;
