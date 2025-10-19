using Microsoft.AspNetCore.Mvc.Razor;

namespace Luma.Server.Utility
{
    public class RazorViewLocationExpander : IViewLocationExpander
    {
        private readonly string? _customPath;

        public RazorViewLocationExpander(string? customPath)
        {
            _customPath = customPath;
        }

        public void PopulateValues(ViewLocationExpanderContext context) { }

        public IEnumerable<string> ExpandViewLocations(
            ViewLocationExpanderContext context,
            IEnumerable<string> viewLocations)
        {
            if (!string.IsNullOrEmpty(_customPath))
            {
                var custom = Path.Combine(_customPath, "{1}", "{0}.cshtml").Replace("\\", "/");
                yield return custom;
            }

            foreach (var loc in viewLocations)
                yield return loc;
        }
    }
}
