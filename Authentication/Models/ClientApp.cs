namespace Authentication.Models
{
    public class ClientApp
    {
        public string Id { get; set; }
        public string Secret { get; set; }
        public string RedirectUrl { get; set; }
        public string Name { get; set; }
    }
}