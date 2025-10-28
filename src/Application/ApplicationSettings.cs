namespace CleanArchitecture.Application
{
    public class ApplicationSettings
    {
        public ApplicationSettings()
        {
            this.SecurityTokenDescriptorKey = default!;
            this.SecurityTokenDescriptorExpiresInMinutes = default!;
            this.SecurityTokenRefreshRate = default!;
            this.DefaultLockoutTimeSpanInMinutes = default!;
            this.MaxFailedAccessAttempts = default!;
            this.ExperimentalIpAddress = default!;
        }

        public string SecurityTokenDescriptorKey { get; private set; }
        public double SecurityTokenDescriptorExpiresInMinutes { get; private set; }
        public double SecurityTokenRefreshRate { get; private set; }
        public double DefaultLockoutTimeSpanInMinutes { get; private set; }
        public int MaxFailedAccessAttempts { get; private set; }
        public string ExperimentalIpAddress { get; private set; }
    }
}
