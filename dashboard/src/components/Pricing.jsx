import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import Section from "./Section";
import Heading from "./Heading";
import Button from "./Button";
import { smallSphere, stars } from "../assets";

const Pricing = () => {
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // Handle file selection
  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
  };

  // Handle file upload
  const handleUpload = async () => {
    if (!file) {
      setMessage("Please select a PDF file.");
      return;
    }

    setLoading(true);
    setMessage("");

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await axios.post("http://localhost:8000/upload_pdf/", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      console.log("Response Data:", response.data); // ✅ Debugging

      if (response.status === 200 && response.data?.report_path) {
        setMessage("File uploaded successfully!");

        // Extract filename from path
        const filename = response.data.report_path.split("/").pop();

        // Navigate to the Upload page with the JSON filename
        navigate(`/upload/${filename}`);
      } else {
        setMessage("Error: No JSON file generated.");
      }
    } catch (error) {
      console.error("Upload error:", error);

      let errorMessage = "Error uploading file.";
      if (error.response) {
        errorMessage += ` Server Response: ${JSON.stringify(error.response.data)}`;
      } else if (error.request) {
        errorMessage += " No response from server.";
      } else {
        errorMessage += ` Request Error: ${error.message}`;
      }

      setMessage(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Section className="overflow-hidden" id="pricing">
      <div className="container relative z-2">
        
        {/* Sphere and Stars Background */}
        <div className="hidden relative justify-center mb-[6.5rem] lg:flex">
          <img src={smallSphere} className="relative z-1" width={255} height={255} alt="Sphere" />
          <div className="absolute top-1/2 left-1/2 w-[60rem] -translate-x-1/2 -translate-y-1/2 pointer-events-none">
            <img src={stars} className="w-full" width={950} height={400} alt="Stars" />
          </div>
        </div>

        {/* Heading */}
        <Heading tag="Get started with THREX" title="Upload CTI Report Here" />

        {/* File Upload Section */}
        <div className="flex flex-col items-center mt-10">
          <input type="file" accept="application/pdf" onChange={handleFileChange} className="mb-4" />
          <Button onClick={handleUpload} disabled={loading}>
            {loading ? "Uploading..." : "Upload"}
          </Button>
          {message && <p className="mt-4 text-center">{message}</p>}
        </div>

        {/* Loading Indicator */}
        {loading && (
          <div className="flex justify-center mt-4">
            <div className="w-6 h-6 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
            <p className="ml-2 text-blue-500">Processing...</p>
          </div>
        )}

        {/* Navigation Link */}
        <div className="flex justify-center mt-10">
          <a className="text-xs font-code font-bold tracking-wider uppercase border-b" href="#how-to-use">
            See the full details
          </a>
        </div>
      </div>
    </Section>
  );
};

export default Pricing;
