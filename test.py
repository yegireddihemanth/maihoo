from google import genai

client = genai.Client(api_key="AIzaSyAM_zHkubqWU4qkfzdnJiz8hzFwJoITjCs")

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="Explain how AI works in a few words",
)

print(response.text)
