
import io
import os
import re
import abc
import csv
import sys
import email
import pathlib
import zipfile
import operator
import functools
import itertools
import posixpath
import collections
from configparser import ConfigParser
from contextlib import suppress
from importlib import import_module
from importlib.abc import MetaPathFinder
from itertools import starmap
__all__ = [
    'Distribution',
    'DistributionFinder',
    'PackageNotFoundError',
    'distribution',
    'distributions',
    'entry_points',
    'files',
    'metadata',
    'requires',
    'version']

class PackageNotFoundError(ModuleNotFoundError):
    '''The package was not found.'''
    pass


def EntryPoint():
    '''EntryPoint'''
    __doc__ = 'An entry point as defined by Python packaging conventions.\n\n    See `the packaging docs on entry points\n    <https://packaging.python.org/specifications/entry-points/>`_\n    for more information.\n    '
    pattern = re.compile('(?P<module>[\\w.]+)\\s*(:\\s*(?P<attr>[\\w.]+))?\\s*(?P<extras>\\[.*\\])?\\s*$')
    
    def load(self):
        '''Load the entry point from its definition. If only a module
        is indicated by the value, return that module. Otherwise,
        return the named object.
        '''
        match = self.pattern.match(self.value)
        module = import_module(match.group('module'))
        if not match.group('attr'):
            attrs = filter(None, ''.split('.'))
            return functools.reduce(getattr, attrs, module)

    
    def module(self):
        match = self.pattern.match(self.value)
        return match.group('module')

    module = property(module)
    
    def attr(self):
        match = self.pattern.match(self.value)
        return match.group('attr')

    attr = property(attr)
    
    def extras(self):
        match = self.pattern.match(self.value)
        if not match.group('extras'):
            return list(re.finditer('\\w+', ''))

    extras = property(extras)
    
    def _from_config(cls, config):
        return (lambda .0 = None: [ cls(name, value, group) for group in .0 for name, value in config.items(group) ])(config.sections())

    _from_config = classmethod(_from_config)
    
    def _from_text(cls, text):
        config = ConfigParser('=', **('delimiters',))
        config.optionxform = str
    # WARNING: Decompyle incomplete

    _from_text = classmethod(_from_text)
    
    def __iter__(self):
        '''
        Supply iter so one may construct dicts of EntryPoints easily.
        '''
        return iter((self.name, self))

    
    def __reduce__(self):
        return (self.__class__, (self.name, self.value, self.group))


EntryPoint = <NODE:26>(EntryPoint, 'EntryPoint', collections.namedtuple('EntryPointBase', 'name value group'))

def PackagePath():
    '''PackagePath'''
    __doc__ = 'A reference to a path in a package'
    
    def read_text(self, encoding = ('utf-8',)):
        pass
    # WARNING: Decompyle incomplete

    
    def read_binary(self):
        pass
    # WARNING: Decompyle incomplete

    
    def locate(self):
        '''Return a path-like object for this path'''
        return self.dist.locate_file(self)


PackagePath = <NODE:26>(PackagePath, 'PackagePath', pathlib.PurePosixPath)

class FileHash:
    
    def __init__(self, spec):
        (self.mode, _, self.value) = spec.partition('=')

    
    def __repr__(self):
        return '<FileHash mode: {} value: {}>'.format(self.mode, self.value)



class Distribution:
    '''A Python distribution package.'''
    
    def read_text(self, filename):
        '''Attempt to load metadata file given by the name.

        :param filename: The name of the file in the distribution info.
        :return: The text if found, otherwise None.
        '''
        pass

    read_text = abc.abstractmethod(read_text)
    
    def locate_file(self, path):
        '''
        Given a path to a file in this distribution, return a path
        to it.
        '''
        pass

    locate_file = abc.abstractmethod(locate_file)
    
    def from_name(cls, name):
        """Return the Distribution for the given package name.

        :param name: The name of the distribution package to search for.
        :return: The Distribution instance (or subclass thereof) for the named
            package, if found.
        :raises PackageNotFoundError: When the named package's distribution
            metadata cannot be found.
        """
        raise PackageNotFoundError(name)

    from_name = classmethod(from_name)
    
    def discover(cls, **kwargs):
        '''Return an iterable of Distribution objects for all packages.

        Pass a ``context`` or pass keyword arguments for constructing
        a context.

        :context: A ``DistributionFinder.Context`` object.
        :return: Iterable of Distribution objects for all packages.
        '''
        context = kwargs.pop('context', None)
        if context and kwargs:
            raise ValueError('cannot accept context and kwargs')
    # WARNING: Decompyle incomplete

    discover = classmethod(discover)
    
    def at(path):
        '''Return a Distribution for the indicated metadata path

        :param path: a string or path-like object
        :return: a concrete Distribution instance for the path
        '''
        return PathDistribution(pathlib.Path(path))

    at = staticmethod(at)
    
    def _discover_resolvers():
        '''Search the meta_path for resolvers.'''
        declared = (lambda .0: pass)(sys.meta_path)
        return filter(None, declared)

    _discover_resolvers = staticmethod(_discover_resolvers)
    
    def _local(cls, root = ('.',)):
        build = build
        meta = meta
        import pep517
        system = build.compat_system(root)
        builder = functools.partial(meta.build, root, system, **('source_dir', 'system'))
        return PathDistribution(zipfile.Path(meta.build_as_zip(builder)))

    _local = classmethod(_local)
    
    def metadata(self):
        '''Return the parsed metadata for this Distribution.

        The returned object will have keys that name the various bits of
        metadata.  See PEP 566 for details.
        '''
        if not self.read_text('METADATA') and self.read_text('PKG-INFO'):
            text = self.read_text('')
            return email.message_from_string(text)

    metadata = property(metadata)
    
    def version(self):
        """Return the 'Version' metadata for the distribution package."""
        return self.metadata['Version']

    version = property(version)
    
    def entry_points(self):
        return EntryPoint._from_text(self.read_text('entry_points.txt'))

    entry_points = property(entry_points)
    
    def files(self):
        '''Files in this distribution.

        :return: List of PackagePath for this distribution or None

        Result is `None` if the metadata file that enumerates files
        (i.e. RECORD for dist-info or SOURCES.txt for egg-info) is
        missing.
        Result may be empty if the metadata exists but is empty.
        '''
        if not self._read_files_distinfo():
            file_lines = self._read_files_egginfo()
        
        def make_file(name = None, hash = None, size_str = None):
            result = PackagePath(name)
            None if hash else result.hash = FileHash(hash)
            None if size_str else result.size = int(size_str)
            result.dist = self
            return result

        if file_lines:
            return list(starmap(make_file, csv.reader(file_lines)))

    files = property(files)
    
    def _read_files_distinfo(self):
        '''
        Read the lines of RECORD
        '''
        text = self.read_text('RECORD')
        if text:
            return text.splitlines()

    
    def _read_files_egginfo(self):
        '''
        SOURCES.txt might contain literal commas, so wrap each line
        in quotes.
        '''
        text = self.read_text('SOURCES.txt')
        if text:
            return map('"{}"'.format, text.splitlines())

    
    def requires(self):
        '''Generated requirements specified for this Distribution'''
        if not self._read_dist_info_reqs():
            reqs = self._read_egg_info_reqs()
            if reqs:
                return list(reqs)

    requires = property(requires)
    
    def _read_dist_info_reqs(self):
        return self.metadata.get_all('Requires-Dist')

    
    def _read_egg_info_reqs(self):
        source = self.read_text('requires.txt')
        if source:
            return self._deps_from_requires_text(source)

    
    def _deps_from_requires_text(cls, source):
        section_pairs = cls._read_sections(source.splitlines())
        sections = (lambda .0: pass# WARNING: Decompyle incomplete
)(itertools.groupby(section_pairs, operator.itemgetter('section')))
        return cls._convert_egg_info_reqs_to_simple_reqs(sections)

    _deps_from_requires_text = classmethod(_deps_from_requires_text)
    
    def _read_sections(lines):
        section = None
        yield locals()
        continue

    _read_sections = staticmethod(_read_sections)
    
    def _convert_egg_info_reqs_to_simple_reqs(sections):
        """
        Historically, setuptools would solicit and store 'extra'
        requirements, including those with environment markers,
        in separate sections. More modern tools expect each
        dependency to be defined separately, with any relevant
        extras and environment markers attached directly to that
        requirement. This method converts the former to the
        latter. See _test_deps_from_requires_text for an example.
        """
        
        def make_condition(name):
            if name:
                return 'extra == "{name}"'.format(name, **('name',))

        
        def parse_condition(section = None):
            if not section:
                section = ''
            (extra, sep, markers) = section.partition(':')
            if extra and markers:
                markers = '({markers})'.format(markers, **('markers',))
                conditions = list(filter(None, [
                    markers,
                    make_condition(extra)]))
                if conditions:
                    return '; ' + ' and '.join(conditions)
                return None

        for section, deps in sections.items():
            for dep in deps:
                yield dep + parse_condition(section)
                return None

    _convert_egg_info_reqs_to_simple_reqs = staticmethod(_convert_egg_info_reqs_to_simple_reqs)


class DistributionFinder(MetaPathFinder):
    '''
    A MetaPathFinder capable of discovering installed distributions.
    '''
    
    class Context:
        __qualname__ = 'DistributionFinder.Context'
        __doc__ = '\n        Keyword arguments presented by the caller to\n        ``distributions()`` or ``Distribution.discover()``\n        to narrow the scope of a search for distributions\n        in all DistributionFinders.\n\n        Each DistributionFinder may expect any parameters\n        and should attempt to honor the canonical\n        parameters defined below when appropriate.\n        '
        name = None
        
        def __init__(self, **kwargs):
            vars(self).update(kwargs)

        
        def path(self):
            '''
            The path that a distribution finder should search.

            Typically refers to Python package paths and defaults
            to ``sys.path``.
            '''
            return vars(self).get('path', sys.path)

        path = property(path)

    
    def find_distributions(self, context = (Context(),)):
        '''
        Find distributions.

        Return an iterable of all Distribution instances capable of
        loading the metadata for packages matching the ``context``,
        a DistributionFinder.Context instance.
        '''
        pass

    find_distributions = abc.abstractmethod(find_distributions)


class FastPath:
    '''
    Micro-optimized class for searching a path for
    children.
    '''
    
    def __init__(self, root):
        self.root = root
        self.base = os.path.basename(self.root).lower()

    
    def joinpath(self, child):
        return pathlib.Path(self.root, child)

    
    def children(self):
        pass
    # WARNING: Decompyle incomplete

    
    def zip_children(self):
        zip_path = zipfile.Path(self.root)
        names = zip_path.root.namelist()
        self.joinpath = zip_path.joinpath
        return dict.fromkeys((lambda .0: pass)(names))

    
    def is_egg(self, search):
        base = self.base
        if base == search.versionless_egg_name and base.startswith(search.prefix):
            return base.endswith('.egg')

    
    def search(self, name):
        pass



class Prepared:
    '''
    A prepared search for metadata on a possibly-named package.
    '''
    normalized = ''
    prefix = ''
    suffixes = ('.dist-info', '.egg-info')
    exact_matches = [
        ''][:0]
    versionless_egg_name = ''
    
    def __init__(self, name):
        self.name = name
        if name is None:
            return None
        self.normalized = None.lower().replace('-', '_')
        self.prefix = self.normalized + '-'
        self.exact_matches = (lambda .0 = None: [ self.normalized + suffix for suffix in .0 ])(self.suffixes)
        self.versionless_egg_name = self.normalized + '.egg'



class MetadataPathFinder(DistributionFinder):
    
    def find_distributions(cls, context = (DistributionFinder.Context(),)):
        '''
        Find distributions.

        Return an iterable of all Distribution instances capable of
        loading the metadata for packages matching ``context.name``
        (or all names if ``None`` indicated) along the paths in the list
        of directories ``context.path``.
        '''
        found = cls._search_paths(context.name, context.path)
        return map(PathDistribution, found)

    find_distributions = classmethod(find_distributions)
    
    def _search_paths(cls, name, paths):
        '''Find metadata directories in paths heuristically.'''
        return None((lambda .0 = None: pass)(map(FastPath, paths)))

    _search_paths = classmethod(_search_paths)


class PathDistribution(Distribution):
    
    def __init__(self, path):
        '''Construct a distribution from a path to the metadata directory.

        :param path: A pathlib.Path or similar object supporting
                     .joinpath(), __div__, .parent, and .read_text().
        '''
        self._path = path

    
    def read_text(self, filename):
        pass
    # WARNING: Decompyle incomplete

    read_text.__doc__ = Distribution.read_text.__doc__
    
    def locate_file(self, path):
        return self._path.parent / path



def distribution(distribution_name):
    '''Get the ``Distribution`` instance for the named package.

    :param distribution_name: The name of the distribution package as a string.
    :return: A ``Distribution`` instance (or subclass thereof).
    '''
    return Distribution.from_name(distribution_name)


def distributions(**kwargs):
    '''Get all ``Distribution`` instances in the current environment.

    :return: An iterable of ``Distribution`` instances.
    '''
    pass
# WARNING: Decompyle incomplete


def metadata(distribution_name):
    '''Get the metadata for the named package.

    :param distribution_name: The name of the distribution package to query.
    :return: An email.Message containing the parsed metadata.
    '''
    return Distribution.from_name(distribution_name).metadata


def version(distribution_name):
    '''Get the version string for the named package.

    :param distribution_name: The name of the distribution package to query.
    :return: The version string for the package as defined in the package\'s
        "Version" metadata key.
    '''
    return distribution(distribution_name).version


def entry_points():
    '''Return EntryPoint objects for all installed packages.

    :return: EntryPoint objects for all installed packages.
    '''
    eps = itertools.chain.from_iterable((lambda .0: pass)(distributions()))
    by_group = operator.attrgetter('group')
    ordered = sorted(eps, by_group, **('key',))
    grouped = itertools.groupby(ordered, by_group)
    return (lambda .0: pass# WARNING: Decompyle incomplete
)(grouped)


def files(distribution_name):
    '''Return a list of files for the named package.

    :param distribution_name: The name of the distribution package to query.
    :return: List of files composing the distribution.
    '''
    return distribution(distribution_name).files


def requires(distribution_name):
    '''
    Return a list of requirements for the named package.

    :return: An iterator of requirements, suitable for
    packaging.requirement.Requirement.
    '''
    return distribution(distribution_name).requires

