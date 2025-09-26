import React from "react";

export default class ErrorBoundary extends React.Component<{children: React.ReactNode}, {hasError: boolean; msg?: string}> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, msg: "" };
  }

  static getDerivedStateFromError(error: any) {
    return { hasError: true, msg: String(error) };
  }

  componentDidCatch(error: any, info: any) {
    console.error("React crash:", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 16, background: "#fee2e2", border: "1px solid #fecaca", borderRadius: 12 }}>
          <h2 style={{ color: "#b91c1c", fontWeight: 600 }}>Dashboard Error</h2>
          <pre style={{ fontSize: 12, color: "#7f1d1d" }}>{this.state.msg}</pre>
        </div>
      );
    }
    return this.props.children;
  }
}
