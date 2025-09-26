import ErrorBoundary from "./ErrorBoundary";
import WazuhSocDashboard from "./WazuhSocDashboard";

export default function App() {
  return (
    <ErrorBoundary>
      <WazuhSocDashboard />
    </ErrorBoundary>
  );
}
