using System;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Xml.Linq;

namespace Authentication.Models
{
    public class ClientAppRepository
    {
        // NHibernate doesn't work in here. Something to do with OWIN I think.

        public ClientApp GetClientAppBytId(string id)
        {
            using (var conn = new SqlConnection(ConfigurationManager.ConnectionStrings["cnSselData"].ConnectionString))
            using (var cmd = new SqlCommand("SELECT * FROM dbo.OAuthClientAudience WHERE AudienceId = @id", conn))
            using (var adap = new SqlDataAdapter(cmd))
            {
                adap.SelectCommand.Parameters.AddWithValue("id", id);
                var dt = new DataTable();
                adap.Fill(dt);

                if (dt.Rows.Count == 0)
                    return null;

                var dr = dt.Rows[0];

                conn.Close();

                var result = new ClientApp()
                {
                    OAuthClientAudienceID = dr.Field<int>("OAuthClientAudienceID"),
                    Id = dr.Field<string>("AudienceId"),
                    Secret = dr.Field<string>("AudienceSecret"),
                    Name = dr.Field<string>("ApplicationName"),
                    Redirects = GetRedirects(dr)
                };

                return result;
            }
        }

        private string[] GetRedirects(DataRow dr)
        {
            var config = XDocument.Parse(dr.Field<string>("Configuration"));
            return config
                 .Element("root")
                 .Element("redirects")
                 .Descendants("add")
                 .Where(x => x.Attribute("key").Value == "uri")
                 .Select(x => x.Attribute("value").Value)
                 .ToArray();
        }

        public void StoreAuthorizationCode(ClientApp app, string username, string token)
        {
            using (var conn = new SqlConnection(ConfigurationManager.ConnectionStrings["cnSselData"].ConnectionString))
            using (var cmd = new SqlCommand("INSERT dbo.OAuthClientAuthorization (OAuthClientAudienceID, ClientID, AuthorizationCode, RedirectUri, State, Expires, IsExchanged, ExchangedOn) VALUES (@OAuthClientAudienceID, @ClientID, @AuthorizationCode, @RedirectUri, @State, @Expires, @IsExchanged, @ExchangedOn)", conn))
            {
                conn.Open();

                cmd.Parameters.AddWithValue("OAuthClientAudienceID", app.OAuthClientAudienceID);
                cmd.Parameters.AddWithValue("ClientID", 0);
                cmd.Parameters.AddWithValue("AuthorizationCode", 0);
                cmd.Parameters.AddWithValue("RedirectUri", 0);
                cmd.Parameters.AddWithValue("State", 0);
                cmd.Parameters.AddWithValue("Expires", 0);
                cmd.Parameters.AddWithValue("IsExchanged", 0);
                cmd.Parameters.AddWithValue("ExchangedOn", 0);

                conn.Close();
            }
        }
    }
}