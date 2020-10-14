namespace Authentication.Models
{
    public class ClientApp
    {
        public int OAuthClientAudienceID { get; set; }
        public string Id { get; set; }
        public string Secret { get; set; }
        public string[] Redirects { get; set; }
        public string Name { get; set; }
    }
}