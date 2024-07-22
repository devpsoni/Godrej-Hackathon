import streamlit as st
from streamlit_extras.switch_page_button import switch_page

def landing_page():
    # Custom CSS for the landing page
    st.markdown("""
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    [data-testid="stSidebar"] {display: none;}
    .hero {
        padding: 5rem 0;
        text-align: center;
    }
    .hero h1 {
        font-size: 4rem;
        margin-bottom: 1rem;
    }
    .hero p {
        font-size: 1.5rem;
        max-width: 800px;
        margin: 0 auto 2rem auto;
    }
    .stButton > button {
        font-size: 1.2rem;
        padding: 0.8rem 2rem;
        background-color: #4CAF50;
        color: white;
        border: none;
        border-radius: 5px;
        cursor: pointer;
        transition: background-color 0.3s;
    }
    .stButton > button:hover {
        background-color: #45a049;
    }
    .features {
        display: flex;
        justify-content: space-around;
        flex-wrap: wrap;
        margin: 4rem 0;
    }
    .feature {
        width: 30%;
        min-width: 250px;
        margin: 1rem;
        padding: 2rem;
        background-color: #1E1E1E;
        border-radius: 10px;
        text-align: center;
    }
    .feature h3 {
        font-size: 1.5rem;
        margin-bottom: 1rem;
    }
    .feature p {
        font-size: 1rem;
    }
    </style>
    """, unsafe_allow_html=True)

    # Hero section
    st.markdown("""
    <div class="hero">
        <h1>Meet Barnaby</h1>
        <p>Your AI-powered research assistant for document analysis and intelligent conversations</p>
    </div>
    """, unsafe_allow_html=True)

    # Center the "Get Started" button
    col1, col2, col3 = st.columns([1,1,1])
    with col2:
        if st.button("Get Started", use_container_width=True, key="get_started_button"):
            switch_page("app")

    # Features section
    st.markdown("""
    <div class="features">
        <div class="feature">
            <h3>Smart Document Analysis</h3>
            <p>Upload PDFs, Word docs, or PowerPoints and get instant insights and summaries.</p>
        </div>
        <div class="feature">
            <h3>Intelligent Q&A</h3>
            <p>Ask questions about your documents and receive accurate, context-aware answers.</p>
        </div>
        <div class="feature">
            <h3>Multiple Chat Sessions</h3>
            <p>Manage multiple research projects with separate chat sessions for each document.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

# Main app logic
def main():
    st.set_page_config(
        page_title="Barnaby - AI Research Assistant",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    landing_page()

if __name__ == "__main__":
    main()