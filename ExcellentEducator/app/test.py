import os
import io
import google.generativeai as genai
import fitz  # PyMuPDF for PDF text extraction

# Configure Gemini AI
genai.configure(api_key="AIzaSyCg6Ubnswv0Or_4XQaEBBiCAeHQbvGlono")

# Gemini AI settings
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
}

def extract_text_from_pdf(pdf_path):
    """Extracts text from a PDF file and ignores images."""
    text = ""
    with open(pdf_path, "rb") as f:
        pdf_binary = f.read()  # Read PDF as binary

    doc = fitz.open(stream=pdf_binary, filetype="pdf")  # Open PDF from binary
    for page in doc:
        text += page.get_text("text") + "\n"  # Extract text from each page
    
    return text.strip()  # Return clean text without extra spaces


BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # App directory
PDF_PATH = os.path.join(BASE_DIR, "static", "about_dr_fox.pdf")
pdf_text = extract_text_from_pdf(PDF_PATH)

model = genai.GenerativeModel(
    model_name="gemini-1.5-flash",
    generation_config=generation_config,
    system_instruction=f"""You are an AI assistant for the business website of Dr. Fox, this website is made for his students and there are products in the shop they can buy, for example: notes/past papers/videos, etc. here is some info about dr. fox: {pdf_text}"""
)

# Start AI chat session
chat_session = model.start_chat(history=[])

# Send extracted text to AI
response = chat_session.send_message(f"hello, who is dr fox")

# Print AI response
print(response.text)