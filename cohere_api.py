import cohere
from dataclasses import dataclass
from get_api_keys import get_api_key_from_trusted_source
from data_extractor import extract_text_from_pdf, extract_text_from_word_document, extract_text_from_ppt

@dataclass
class CONFIG:
    COHERE_API_KEY = get_api_key_from_trusted_source(trusted=True)

pdf_context = extract_text_from_pdf("PDFs/GCPL_Annual_Report_2022_23[1].pdf")
word_context = extract_text_from_word_document("Word/EC Transcripts Course 6 Rahil Parikh.docx")
ppt_context = extract_text_from_ppt("PPT/Indian-FMCG-Industry-Presentation[1].pptx")

# print(pdf_context)
# print(word_context)
# print(ppt_context)

def cohere_output_generation(question, context):
    co = cohere.Client(CONFIG.COHERE_API_KEY)
    response = co.generate(
        model="command",
        truncate="END",
        prompt=f"Question: {question}\nContext: {context}\nAnswer:",
        max_tokens=1024
    )

    return response.generations[0].text.strip()

response = cohere_output_generation("Briefly summarize the content provided.", pdf_context)
print(response)
# response = cohere_output_generation("What is the word document about?", word_context)
# print(response)
# response = cohere_output_generation("Give me 3 key takeaways in paragraph format.", ppt_context)
# print(response)
