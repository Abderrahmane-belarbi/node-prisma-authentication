import { Route, Routes } from 'react-router-dom'
import './App.css'
import MainLayout from './layouts/main-layout'
import Login from './components/auth/login'

function App() {

  return (
    <Routes>
      <Route element={<MainLayout />}>
        <Route index element={<section className="form-panel">Home</section>} />
        <Route path="login" element={<Login />} />
      </Route>
    </Routes>
  )
}

export default App
