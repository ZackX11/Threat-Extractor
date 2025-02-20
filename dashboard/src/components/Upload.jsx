import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import Button from "./Button";
const Upload = () => {
  const { filename } = useParams();
  const [jsonData, setJsonData] = useState(null);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    axios.get(`http://localhost:8000/get_json/${filename}`)
      .then((response) => setJsonData(response.data))
      .catch(() => setError("Failed to load JSON data."));
  }, [filename]);

  const handleDownload = () => {
    if (!jsonData) return;

    const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement("a");
    link.href = url;
    link.download = filename || "download.json";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <h1>Upload Successful!</h1>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {jsonData ? <pre>{JSON.stringify(jsonData, null, 4)}</pre> : <p>Loading JSON data...</p>}
      
      <Button onClick={() => navigate(-1)}>Go Back</Button>
      {jsonData && <Button onClick={handleDownload} style={{ marginLeft: "10px" }} white>Download JSON</Button>}
    </div>
  );
};

export default Upload;
