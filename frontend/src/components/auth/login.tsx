import {
  ArrowRight,
  CheckCircle2,
  LockKeyhole,
  ShieldCheck,
  X,
} from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { Brand } from "../brand";
import { useState, type FormEvent } from "react";
import GoogleMark from "../svg/google-mark";
import Footer from "./footer";
import Field from "./field";

export default function Login() {
  const navigate = useNavigate();
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  function googleSignIn() {
    setNotice("Demo sign-in complete. Redirecting to your account…");
    window.setTimeout(() => {
      sessionStorage.setItem("northstar-demo-session", "1");
      navigate("/auth/complete");
    }, 500);
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setNotice("");
    setBusy(true);
    window.setTimeout(() => {
      setBusy(false);
      if (email.toLowerCase().includes("unverified")) {
        setError("Please verify your email address before signing in.");
        return;
      }
      sessionStorage.setItem("northstar-demo-session", "1");
      navigate("/account");
    }, 550);
  }

  return (
    <section className="form-panel">
      <div className="form-top">
        <span>Already have an account?</span>
        <Link to={"/register"}>
          Create account
          <ArrowRight size={15} />
        </Link>
      </div>
      <div className="form-inner">
        <Link to="/login" className="mobile-brand">
          <Brand />
        </Link>
        <div className="form-heading">
          <div className="heading-icon">
            <LockKeyhole size={20} />
          </div>
          <h1>Welcome back</h1>
          <p className="subtitle">Enter your details to access your account.</p>
        </div>
        {notice && (
          <div className="feedback success" role="status">
            <CheckCircle2 size={18} />
            <div>{notice}</div>
          </div>
        )}
        {error && (
          <div className="feedback error" role="alert">
            <X size={17} />
            <div>
              {error}
              <button
                className="feedback-link"
                onClick={() =>
                  setNotice("A fresh verification link has been sent.")
                }
              >
                Resend verification email
              </button>
            </div>
          </div>
        )}

        <button className="google-button" onClick={googleSignIn}>
          <GoogleMark /> Continue with Google
        </button>
        <div className="divider">
          <span>or continue with email</span>
        </div>
        <form onSubmit={submit} className="auth-form">
          <Field
            label="Email address"
            id="email"
            type="email"
            placeholder="you@example.com"
            value={email}
            onChange={setEmail}
            autoComplete="email"
          />
          <Field
            label="Password"
            id="password"
            type="password"
            placeholder="Enter your password"
            value={password}
            onChange={setPassword}
            autoComplete="current-password"
          />
          <div className="forgot-line">
            <Link to="/forgot-password">Forgot password?</Link>
          </div>
          <button className="primary-button" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"} <ArrowRight size={17} />
          </button>
        </form>
        <p className="form-legal">
          By continuing, you agree to our <a href="#terms">Terms</a> and{" "}
          <a href="#privacy">Privacy Policy</a>.
        </p>

        <div className="trust-note">
          <ShieldCheck size={15} />
          <span>Your information is protected with end-to-end security.</span>
        </div>
      </div>
      <Footer />
    </section>
  );
}
