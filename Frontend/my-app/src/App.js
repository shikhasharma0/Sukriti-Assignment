// frontend/src/App.js
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import Home from './components/Home';
import { useSelector } from 'react-redux';

const App = () => {
  const token = useSelector(state => state.auth.token);

  return (
    <Router>
      <Routes>
        <Route path="/" element={!token ? <Login /> : <Navigate to="/home" />} />
        <Route path="/register" element={!token ? <Register /> : <Navigate to="/home" />} />
        <Route path="/home" element={token ? <Home /> : <Navigate to="/" />} />
      </Routes>
    </Router>
  );
};

export default App;
