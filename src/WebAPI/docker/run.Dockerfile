# syntax=docker/dockerfile:1

# Use official ASP.NET Core sdk image
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS runtime

# Set the working directory inside the container
WORKDIR /app

# Copy the src components from your local folder
COPY src/Core/ ./Core/
COPY src/WebAPI/ ./WebAPI/

# Set the final working directory to the entrypoint module
# This ensures the startup command runs in the correct context.
WORKDIR /app/WebAPI

# Set the entry point for the container and launch with the Docker profile
ENTRYPOINT ["dotnet", "run", "--launch-profile", "Docker"]
