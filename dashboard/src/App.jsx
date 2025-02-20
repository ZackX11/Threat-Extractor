import ButtonGradient from "./assets/svg/ButtonGradient";
import Benefits from "./components/Benefits";
import Footer from "./components/Footer";
import Header from "./components/Header";
import Hero from "./components/Hero";
import Pricing from "./components/Pricing";
import Roadmap from "./components/Roadmap";
import Services from "./components/Services";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Upload from "./components/Upload";

const App = () => {
  return (
    <>
      <div className="pt-[4.75rem] lg:pt-[5.25rem] overflow-hidden">
      <Header />
      <Routes>  {/*  No extra <Router> here */}
        <Route path="/" element={ 
          <>
            <Hero />
            <Benefits />
            <Services />
            <Pricing />
          </>
        } />
        <Route path="/upload/:filename" element={<Upload />} />
      </Routes>
      <Footer />
    </div>

      <ButtonGradient />
    </>
  );
};

export default App;
